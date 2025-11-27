import QtQuick 2.2
import QtQuick.Controls 1.0
import QtQuick.Layouts 1.0
import im.ricochet 1.0

ApplicationWindow {
    id: window
    width: minimumWidth
    height: minimumHeight
    minimumWidth: 400
    maximumWidth: minimumWidth
    minimumHeight: visibleItem.height + 16
    maximumHeight: minimumHeight
    title: "Ricochet"

    signal networkReady
    signal closed

    onVisibleChanged: if (!visible) closed()

    property Item visibleItem: configPage.visible ? configPage : pageLoader.item

    function openBeginning() {
        configPage.visible = false;
        pageLoader.sourceComponent = firstPage
        pageLoader.visible = true
    }

    function openConfig() {
        pageLoader.visible = false
        configPage.init();
        configPage.visible = true
    }

    function openBootstrap() {
        configPage.visible = false
        pageLoader.source = Qt.resolvedUrl("TorBootstrapStatus.qml")
        pageLoader.visible = true
    }

    Loader {
        id: pageLoader
        anchors {
            top: parent.top
            left: parent.left
            right: parent.right
            margins: 8
        }
        sourceComponent: firstPage
    }

    TorConfigurationPage {
        id: configPage
        anchors {
            top: parent.top
            left: parent.left
            right: parent.right
            margins: 8
        }
        visible: false
    }

    Component {
        id: firstPage

        Column {
            spacing: 8

            Label {
                width: parent.width
                //: A label with directions for when to use the 'Connect' button
                text: qsTr("This computer's Internet connection is free of obstacles. I would like to connect directly to the Tor network.")
                wrapMode: Text.Wrap
                horizontalAlignment: Qt.AlignHCenter
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                //: Label for button to connect to the Tor network
                text: qsTr("Connect")
                isDefault: true
                enabled: true
                onClicked: {
                    torControl.beginBootstrap();
                    window.openBootstrap();
                }
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.onPressAction: {
                    torControl.beginBootstrap();
                    window.openBootstrap();
                }
            }

            Rectangle {
                height: 1
                width: parent.width
                color: palette.mid
            }

            Label {
                width: parent.width
                //: A label with directions for when to use the 'Configure' button
                text: qsTr("This computer's Internet connection is censored, filtered, or proxied. I need to configure network settings.")
                wrapMode: Text.Wrap
                horizontalAlignment: Qt.AlignHCenter
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                //: Label for button to configure the Tor daemon beore connecting to the Tor network
                text: qsTr("Configure")
                onClicked: window.openConfig()
                enabled: true

                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.onPressAction: {
                    window.openConfig()
                }
            }
        }
    }

    Action {
        shortcut: StandardKey.Close
        onTriggered: window.close()
    }
}
