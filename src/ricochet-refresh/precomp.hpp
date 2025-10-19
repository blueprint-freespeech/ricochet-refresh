// pull in Q_OS_ defines
#include <QtGlobal>

// C standard library
#include <limits.h>

// C++ standard library
#include <sstream>
#include <iomanip>
#include <cassert>
#include <type_traits>
#include <cstdint>
#include <functional>
#include <fstream>
#include <iterator>
#include <set>
#include <random>

// Windows
#if defined(Q_OS_WIN)
#   include <windows.h>
#endif

// fmt
#include <fmt/format.h>
#include <fmt/ostream.h>

// Qt
#if defined(Q_OS_WIN)
#   include <QAbstractNativeEventFilter>
#endif
#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QGuiApplication>
#include <QHostAddress>
#include <QIcon>
#include <QJsonArray>
#include <QJsonObject>
#include <QLibraryInfo>
#include <QLockFile>
#ifdef Q_OS_MAC
#   include <QtMac>
#endif // Q_OS_MAC
#include <QMessageBox>
#include <QObject>
#include <QQuickItem>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QScreen>
#include <QSettings>
#include <QStandardPaths>
#include <QtQml>
#include <QTranslator>

// tego
#include <tego/tego.hpp>

#ifdef TEGO_VERSION
#   define TEGO_STR2(X) #X
#   define TEGO_STR(X) TEGO_STR2(X)
#   define TEGO_VERSION_STR TEGO_STR(TEGO_VERSION)
#else
#   define TEGO_VERSION_STR "devbuild"
#endif
