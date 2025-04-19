use crate::v3::Error;

#[derive(Debug, PartialEq)]
pub struct IntroductionPacket {
    versions: Vec<Version>,
}

impl IntroductionPacket {
    pub fn new(versions: Vec<Version>) -> Result<Self, Error> {
        if versions.is_empty() {
            Err(Error::PacketConstructionFailed("introduction packet must have specify at least one supported version".to_string()))
        } else if versions.len() > u8::MAX as usize {
            Err(Error::PacketConstructionFailed("introduction packet may have no more than 255 supported version".to_string()))
        } else {
            Ok(Self{versions})
        }
    }

    pub fn versions(&self) -> &Vec<Version> {
        &self.versions
    }

    pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), Error> {

        v.push(0x49u8);
        v.push(0x4du8);
        v.push(self.versions.len() as u8);
        for ver in &self.versions {
            v.push(ver.into());
        }

        Ok(())
    }
}

impl TryFrom<&[u8]> for IntroductionPacket {
    type Error = crate::v3::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match bytes.len() {
            0 => Err(Self::Error::NeedMoreBytes),
            1 => if bytes[0] == 0x49 {
                Err(Self::Error::NeedMoreBytes)
            } else {
                Err(Self::Error::InvalidIntroductionPacket)
            },
            2 => if bytes[0] == 0x49 && bytes[1] == 0x4d {
                Err(Self::Error::NeedMoreBytes)
            } else {
                Err(Self::Error::InvalidIntroductionPacket)
            },
            3 => if bytes[0] == 0x49 && bytes[1] == 0x4d && bytes[3] >= 1 {
                Err(Self::Error::NeedMoreBytes)
            } else {
                Err(Self::Error::InvalidIntroductionPacket)
            }
            count => if bytes[0] == 0x49 && bytes[1] == 0x4d && bytes[3] >= 1 {
                if count >= 3usize + bytes[3] as usize {
                    Err(Self::Error::NeedMoreBytes)
                } else {
                    let version_count = bytes[2] as usize;
                    let mut versions: Vec<Version> = Vec::with_capacity(version_count);
                    for i in 0..version_count {
                        versions.push(bytes[3 + i].try_into()?);
                    }

                    Ok(IntroductionPacket{versions})
                }
            } else {
                Err(Self::Error::InvalidIntroductionPacket)
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct IntroductionResponsePacket {
    pub version: Option<Version>,
}

impl IntroductionResponsePacket {
    pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), Error> {
        if let Some(version) = &self.version {
            v.push(version.into());
        } else {
            v.push(0xffu8);
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for IntroductionResponsePacket {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match bytes.len() {
            0 => Err(Self::Error::NeedMoreBytes),
            _count => if bytes[0] == 0xff {
                Ok(IntroductionResponsePacket{version: None})
            } else {
                let version: Version = bytes[0].try_into()?;
                Ok(IntroductionResponsePacket{version: Some(version)})
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Version {
    Ricochet1_0,
    Ricochet1_1,
    RicochetRefresh3,
}

impl From<&Version> for u8 {
    fn from(version: &Version) -> u8 {
        match version {
            Version::Ricochet1_0 => 0u8,
            Version::Ricochet1_1 => 1u8,
            Version::RicochetRefresh3 => 3u8,
        }
    }
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::Ricochet1_0),
            1 => Ok(Version::Ricochet1_1),
            3 => Ok(Version::RicochetRefresh3),
            _ => Err(Self::Error::InvalidVersion(value))
        }
    }
}
