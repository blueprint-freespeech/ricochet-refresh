/* Ricochet Refresh - https://ricochetrefresh.net/
 * Copyright (C) 2020, Blueprint For Free Speech <ricochet@blueprintforfreespeech.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 *    * Neither the names of the copyright owners nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "FileChannel.h"
#include "Channel_p.h"
#include "Connection.h"
#include "utils/SecureRNG.h"
#include "utils/Useful.h"

#include "context.hpp"
#include "error.hpp"
#include "globals.hpp"
#include "file_hash.hpp"
using tego::g_globals;

using namespace Protocol;

FileChannel::outgoing_transfer_record::outgoing_transfer_record(const std::string& filePath, qint64 fileSize)
: size(fileSize)
, offset(0)
, cur_chunk(0)
, stream(filePath, std::ios::in | std::ios::binary)
, chunkBuffer(std::make_unique<char[]>(FileMaxChunkSize))
{ }

FileChannel::incoming_transfer_record::incoming_transfer_record(qint64 fileSize, const std::string& fileHash, chunk_id_t chunkCount)
: size(fileSize)
, cur_chunk(0)
, missing_chunks(chunkCount)
, sha3_512(fileHash)
, stream()
{ }

std::string FileChannel::incoming_transfer_record::partial_dest() const
{
    return  dest + ".part";
}

void FileChannel::incoming_transfer_record::open_stream(const std::string& dest)
{
    this->dest = dest;

    // attempt to open the destination for reading and writing
    // discard previous contents
    // binary mode
    // we need to read to validate the hash after the transfer completes
    this->stream.open(this->partial_dest(), std::ios::in | std::ios::out | std::ios::trunc | std::ios::binary);
    TEGO_THROW_IF_FALSE(this->stream.is_open());
}

FileChannel::FileChannel(Direction direction, Connection *connection)
    : Channel(QStringLiteral("im.ricochet.file-transfer"), direction, connection)
{
}

size_t FileChannel::fsize_to_chunks(size_t sz)
{
    return (sz + (FileMaxChunkSize - 1)) / FileMaxChunkSize;
}

bool FileChannel::allowInboundChannelRequest(
    const Data::Control::OpenChannel*,
    Data::Control::ChannelResult *result)
{
    if (connection()->purpose() != Connection::Purpose::KnownContact) {
        qDebug() << "Rejecting request for" << type() << "channel from connection with purpose" << int(connection()->purpose());
        result->set_common_error(Data::Control::ChannelResult::UnauthorizedError);
        return false;
    }

    if (connection()->findChannel<FileChannel>(Channel::Inbound)) {
        qDebug() << "Rejecting request for" << type() << "channel because one is already open";
        return false;
    }

    return true;
}

bool FileChannel::allowOutboundChannelRequest(
    Data::Control::OpenChannel*)
{
    if (connection()->findChannel<FileChannel>(Channel::Outbound)) {
        BUG() << "Rejecting outbound request for" << type() << "channel because one is already open on this connection";
        return false;
    }

    if (connection()->purpose() != Connection::Purpose::KnownContact) {
        BUG() << "Rejecting outbound request for" << type() << "channel for connection with unexpected purpose" << int(connection()->purpose());
        return false;
    }

    return true;
}

void FileChannel::receivePacket(const QByteArray &packet)
{
    Data::File::Packet message;
    if (!message.ParseFromArray(packet.constData(), packet.size())) {
        qWarning() << "failed to parse message on file channel";
        closeChannel();
        return;
    }

    if (message.has_file_header()) {
        handleFileHeader(message.file_header());
    } else if (message.has_file_chunk()) {
        handleFileChunk(message.file_chunk());
    } else if (message.has_file_chunk_ack()) {
        handleFileChunkAck(message.file_chunk_ack());
    } else if (message.has_file_header_ack()) {
        handleFileHeaderAck(message.file_header_ack());
    } else {
        qWarning() << "Unrecognized file packet on " << type();
        closeChannel();
    }
}

void FileChannel::handleFileHeader(const Data::File::FileHeader &message)
{
    if (direction() != Inbound) {
        qWarning() << "Rejected inbound message (FileHeader) on an outbound channel";
    } else if (!message.has_size() || !message.has_chunk_count()) {
        /* rationale:
         *  - if there's no size, we know when we've reached the end when cur_chunk == n_chunks
         *  - if there's no chunk count, we know when we've reached the end when total_bytes >= size
         *  - if there's neither, size cannot be determined */
        /* TODO: given ^, are both actually needed? */
        qWarning() << "Rejected file header with missing size";
    } else if (!message.has_sha3_512()) {
        qWarning() << "Rejected file header with missing hash (sha3_512) - cannot validate";
    } else if (!message.has_file_id()) {
        qWarning() << "Rejected file header with missing id";
    } else if (!message.has_chunk_count()) {
        qWarning() << "Rejected file header with missing chunk count";
    } else if (!message.has_name()) {
        qWarning() << "Rejected file header with missing name";
    } else if (message.name().find("..") != std::string::npos) {
        qWarning() << "Rejected file header with name containing '..'";
    } else if (message.name().find("/") != std::string::npos) {
        qWarning() << "Rejected file header with name containing '/'";
    } else {
        const auto id = message.file_id();
        incoming_transfer_record ifr(message.size(), message.sha3_512(), message.chunk_count());

        // TODO: change the protocol to send a byte buffer of the exact size?
        TEGO_THROW_IF_FALSE_MSG(ifr.sha3_512.size() == (tego_file_hash::STRING_SIZE - 1));
        tego_file_hash fileHash;
        fileHash.hex = ifr.sha3_512;

        // signal the file transfer request
        emit this->fileRequestReceived(id, QString::fromStdString(message.name()), ifr.size, std::move(fileHash));

        incomingTransfers.insert({id, std::move(ifr)});
    }
}

void FileChannel::handleFileChunk(const Data::File::FileChunk &message)
{
    auto response = std::make_unique<Data::File::FileChunkAck>();
    response->set_file_chunk_id(message.chunk_id());
    response->set_file_id(message.file_id());
    response->set_accepted(false);

    auto it = incomingTransfers.find(message.file_id());
    if (it == incomingTransfers.end()) {
        qWarning() << "rejecting chunk for unknown file";
        response->set_accepted(false);
    }
    else if (message.chunk_size() > FileMaxChunkSize ||
        message.chunk_size() != message.chunk_data().length())
    {
        qWarning() << "rejecting chunk because size mismatch";
        response->set_accepted(false);
    }
    else
    {
        tego_file_hash chunkHash(
            reinterpret_cast<uint8_t const*>(message.chunk_data().c_str()),
            reinterpret_cast<uint8_t const*>(message.chunk_data().c_str()) + message.chunk_size());

        logger::println("Receiving file:chunk {}:{} with hash: {}", message.file_id(), message.chunk_id(), chunkHash.to_string());

        if (chunkHash.to_string() != message.sha3_512())
        {
            response->set_accepted(false);
        }
        else
        {
            response->set_accepted(true);

            auto& itr = it->second;
            itr.stream.write(message.chunk_data().c_str(), message.chunk_size());
            itr.missing_chunks--;

            // emit progress callback
            const auto fileId = message.file_id();
            const auto written = message.chunk_id() * FileMaxChunkSize + message.chunk_size();
            const auto total = itr.size;

            emit this->fileTransferProgress(fileId, tego_attachment_direction_receiving, written, total);

            if (itr.missing_chunks == 0)
            {

                /* sha3_512 validation */

                // reset the read/write stream and calculate the file hash
                itr.stream.seekg(0);
                tego_file_hash fileHash(itr.stream);
                itr.stream.close();

                // delete file if calculated hash doesn't match expected
                if (fileHash.to_string() != itr.sha3_512)
                {
                    //todo: handle this better, error should probably surface to user yeah?
                    QDir dir;
                    dir.remove(QString::fromStdString(itr.partial_dest()));
                    closeChannel();
                    TEGO_THROW_MSG("Hash of completed file {} is {}, was expecting {}", itr.partial_dest(), fileHash.to_string(),itr.sha3_512);
                    return;
                }

                // if a file already exists at our final destination, then remove it
                const auto qDest = QString::fromStdString(itr.dest);
                if (QFile::exists(qDest))
                {
                    TEGO_THROW_IF_FALSE(QFile::remove(qDest));
                }

                const auto qPartialDest = QString::fromStdString(itr.partial_dest());
                TEGO_THROW_IF_FALSE(QFile::rename(qPartialDest, qDest));

                incomingTransfers.erase(it);
                // todo: erase tmp dir (or better yet, put the temp dir in the same place as our destination path)
            }
        }
    }

    Data::File::Packet packet;
    packet.set_allocated_file_chunk_ack(response.release());
    Channel::sendMessage(packet);
}

void FileChannel::handleFileChunkAck(const Data::File::FileChunkAck &message)
{
    const auto id = message.file_id();

    auto it = outgoingTransfers.find(id);
    if (it == outgoingTransfers.end() ||
        it->second.cur_chunk != message.file_chunk_id())
    {
        qWarning() << "recieved ack for a chunk we never sent";
        return;
    }
    auto& otr = it->second;

    // see if we are done sending chunks
    if (otr.finished())
    {
        outgoingTransfers.erase(it);
        return;
    }

    // increment chunk index for sendChunkWithId
    if(message.accepted())
    {
        otr.cur_chunk++;
        sendNextChunk(id);
    }
    else
    {
        outgoingTransfers.erase(it);
    }
}

void FileChannel::handleFileHeaderAck(const Data::File::FileHeaderAck &message)
{
    if (direction() != Outbound) {
        qWarning() << "Rejected inbound message on inbound file channel";
        return;
    }

    const auto id = message.file_id();

    auto it = outgoingTransfers.find(id);
    if (it == outgoingTransfers.end())
    {
        qWarning() << "recieved ack for a file header we never sent";
        return;
    }

    /* start the transfer at chunk 0 */
    if (message.accepted())
    {
        sendNextChunk(id);
    }
    else
    {
        // receiver rejectd our transfer request, so erase it from our records
        outgoingTransfers.erase(it);
    }
}

bool FileChannel::sendFileWithId(QString file_uri,
                                 QString file_hash,
                                 QDateTime,
                                 file_id_t file_id)
{
    if (direction() != Outbound) {
        BUG() << "Attempted to send outbound message on non outbound channel";
        return false;
    }

    if (file_uri.isEmpty()) {
        BUG() << "File URI is empty, this should never have been reached";
        return false;
    }

    /* only allow regular files or symlinks chains to regular files */
    QFileInfo fi(file_uri);
    auto file_path = fi.canonicalFilePath().toStdString();
    if (file_path.size() == 0) {
        qWarning() << "Could net resolve file path";
        return false;
    }

    const auto file_size = fi.size();
    const auto file_chunks = fsize_to_chunks(file_size);

    // create our record
    outgoing_transfer_record qf(file_path, file_size);
    if (!qf.stream.is_open())
    {
        qWarning() << "Failed to open file for sending header";
        return false;
    }
    outgoingTransfers.insert({file_id, std::move(qf)});

    auto header = std::make_unique<Data::File::FileHeader>();
    header->set_file_id(file_id);
    header->set_size(file_size);
    header->set_chunk_count(file_chunks);
    header->set_sha3_512(file_hash.toStdString());
    header->set_name(fi.fileName().toStdString());

    Data::File::Packet packet;
    packet.set_allocated_file_header(header.release());

    Channel::sendMessage(packet);

    /* the first chunk will get sent after the first header ack */
    return true;
}

void FileChannel::acceptFile(tego_attachment_id_t fileId, const std::string& dest)
{
    auto it = incomingTransfers.find(fileId);
    TEGO_THROW_IF_FALSE(it != incomingTransfers.end());
    auto& itr = it->second;
    itr.open_stream(dest);

    auto response = std::make_unique<Data::File::FileHeaderAck>();
    response->set_accepted(true);
    response->set_file_id(fileId);

    Data::File::Packet packet;
    packet.set_allocated_file_header_ack(response.release());
    Channel::sendMessage(packet);
}

void FileChannel::rejectFile(tego_attachment_id_t fileId)
{
    auto it = incomingTransfers.find(fileId);
    TEGO_THROW_IF_FALSE(it != incomingTransfers.end());

    // remove the incoming_transfer_record from our list on reject
    incomingTransfers.erase(it);

    auto response = std::make_unique<Data::File::FileHeaderAck>();
    response->set_accepted(false);
    response->set_file_id(fileId);

    Data::File::Packet packet;
    packet.set_allocated_file_header_ack(response.release());
    Channel::sendMessage(packet);
}

void FileChannel::cancelTransfer(tego_attachment_id_t fileId)
{

}

bool FileChannel::sendNextChunk(file_id_t id)
{
    if (direction() != Outbound) {
        BUG() << "Attempted to send outbound message on non outbound channel";
        return false;
    }

    auto it = outgoingTransfers.find(id);
    if (it == outgoingTransfers.end())
    {
        BUG() << "Attemping to send next chunk for unknown file" << id;
        return false;
    }
    auto& otr = it->second;

    auto& chunkBuffer = otr.chunkBuffer;

    // make sure our offset and the stream offset agree
    Q_ASSERT(otr.finished() == false);
    Q_ASSERT(otr.offset == otr.stream.tellg());
    Q_ASSERT(otr.offset == otr.cur_chunk * FileMaxChunkSize);

    // read the next chunk to our buffer, and update our offset
    otr.stream.read(chunkBuffer.get(), FileMaxChunkSize);
    const auto chunkSize = otr.stream.gcount();
    otr.offset += chunkSize;

    // calculate this chunks hash
    tego_file_hash chunkHash(
        reinterpret_cast<uint8_t const*>(chunkBuffer.get()),
        reinterpret_cast<uint8_t const*>(chunkBuffer.get() + chunkSize));

    // build our chunk
    auto chunk = std::make_unique<Data::File::FileChunk>();
    chunk->set_sha3_512(chunkHash.to_string());
    chunk->set_file_id(id);
    chunk->set_chunk_id(otr.cur_chunk);
    chunk->set_chunk_size(chunkSize);
    chunk->set_chunk_data(chunkBuffer.get(), chunkSize);

    Data::File::Packet packet;
    packet.set_allocated_file_chunk(chunk.release());

    // send the chunk
    Channel::sendMessage(packet);

    // emit for callback
    emit this->fileTransferProgress(id, tego_attachment_direction_sending, otr.offset, otr.size);

    return true;
}
