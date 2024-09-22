import QtQuick
import QtQuick.Controls.Basic
import QtQuick
import QtQuick.Controls.Basic
ApplicationWindow {
    visible: true
    width: 600
    height: 500
    title: "PrecePt test app"
    property string displayText: "Enjoy!"
    Rectangle {
        anchors.fill: parent
        Image {
            sourceSize.width: parent.width
            sourceSize.height: parent.height
            source: "./image.jpg"
            fillMode: Image.PreserveAspectFit
        }
        Text {
            anchors.centerIn: parent
            text: displayText
            font.pixelSize: 48
            color: "white"
        }
    }
}