import QtQuick
import QtQuick.Controls.Basic
import QtQuick
import QtQuick.Controls.Basic
ApplicationWindow {
    visible: true
    width: 600
    height: 500
    x: (screen.desktopAvailableWidth / 2) + 12
    y: (screen.desktopAvailableHeight / 2) - (height / 2)
    title: "PrecePt test app"
    Rectangle {
        anchors.fill: parent
        Image {
            sourceSize.width: parent.width
            sourceSize.height: parent.height
            source: "./decrypted/image.jpg"
            fillMode: Image.PreserveAspectFit
        }
    }
}