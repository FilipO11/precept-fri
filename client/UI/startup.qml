import QtQuick
import QtQuick.Controls.Basic
import QtQuick
import QtQuick.Controls.Basic
ApplicationWindow {
    visible: true
    width: 600
    height: 500
    x: (screen.desktopAvailableWidth / 2) - width - 12
    y: (screen.desktopAvailableHeight / 2) - (height / 2)
    title: "Loading PrecePt test app"
    property string displayText: "Waiting for license agent..."
    property QtObject backend
    Rectangle {
        anchors.fill: parent
        Text {
            anchors.centerIn: parent
            text: displayText
            font.pixelSize: 24
            color: "black"
        }
    }

    Connections {
        target: backend
        function onUpdated(msg) {
            displayText = msg;
        }
    }
}