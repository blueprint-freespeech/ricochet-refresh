import QtQuick 2.0
import QtQuick.Controls 1.0
import QtQuick.Controls.Styles 1.0
import QtQuick.Layouts 1.0
import im.ricochet 1.0
import "utils.js" as Utils

FocusScope {
    id: contactId
    z: 4
    height: layout.height
    Layout.fillWidth: true

    property alias text: field.text
    property alias readOnly: field.readOnly
    property alias horizontalAlignment: field.horizontalAlignment
    property bool acceptableInput: false
    property bool showCopyButton: true

    RowLayout {
        id: layout
        width: parent.width

        TextField {
            id: field
            Layout.fillWidth: true
            validator: readOnly ? null : idValidator
            placeholderText: "ricochet:"
            focus: true

            ContactIDValidator {
                id: idValidator

                onAcceptable: {
                    contactId.acceptableInput = true;
                    errorBubble.clear()
                }

                onIntermediate: {
                    contactId.acceptableInput = false;
                    errorBubble.clear()
                }

                onInvalidServiceId : {
                    contactId.acceptableInput = false;
                    errorBubble.show(qsTr("This ID is invalid"));
                }

                onMatchesContact: function(nickname) {
                    contactId.acceptableInput = false;
                    errorBubble.show(qsTr("<b>%1</b> is already your contact").arg(Utils.htmlEscaped(nickname)))
                }

                onMatchesSelf: {
                    contactId.acceptableInput = false;
                    errorBubble.show(qsTr("You can't add yourself as a contact"))
                }
            }

            Bubble {
                id: errorBubble
                target: field
                horizontalAlignment: Qt.AlignLeft
                textFormat: Text.RichText

                function show(value) {
                    text = value
                    opacity = 1
                }

                function clear() {
                    opacity = 0
                }
            }

            function copyLoudly() {
                // The Clipboard helper also copies to the X11 selection clipboard
                Clipboard.copyText(field.text)
                copyBubble.displayed = true
                bubbleResetTimer.start()
            }

            MouseArea {
                anchors.fill: parent
                enabled: field.readOnly
                onClicked: field.copyLoudly()
            }

            Bubble {
                id: copyBubble
                target: field
                //: Message displayed when text is copied to the user's clipboard
                text: qsTr("Copied to clipboard")
                displayed: false
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }

            Timer {
                id: bubbleResetTimer
                interval: 1000
                onTriggered: copyBubble.displayed = false
            }
        }

        Button {
            //: Text displayed on a button used to copy somethign to the user's clipboard
            text: qsTr("Copy")
            visible: contactId.showCopyButton
            onClicked: field.copyLoudly()

            Accessible.role: Accessible.Button
            Accessible.name: text
            //: Text description of ricochet id copy button for accessibility tech like screen readers
            Accessible.description: qsTr("Copies the ricochet id to the clipboard")
            Accessible.onPressAction: field.copyLoudly()
        }
    }
}

