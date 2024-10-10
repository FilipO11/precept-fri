import shutil
import sys, os, threading, zmq, subprocess, atexit
from time import sleep
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtQml import QQmlApplicationEngine
from PyQt6.QtQuick import QQuickWindow
from PyQt6.QtCore import QObject, pyqtSignal

LICENSEAGENT = "tcp://localhost:8100"


def cleanup():
    laproc.kill()
    # shutil.rmtree(os.path.join("UI/decrypted"), ignore_errors=True)


class Backend(QObject):
    def __init__(self):
        QObject.__init__(self)

    updated = pyqtSignal(str, arguments=["updater"])

    def updater(self, display_text):
        self.updated.emit(display_text)

    def bootUp(self):
        global laproc
        laproc = subprocess.Popen(
            ["C:/Python312/python.exe", "./LicenseAgent.py"], stdout=subprocess.DEVNULL
        )
        t_thread = threading.Thread(target=self._bootUp)
        t_thread.daemon = True
        t_thread.start()

    def _bootUp(self):
        message = None
        while message != b"acquired":
            socket.send(b"liccheck")
            message = socket.recv()
            if message == b"requesting":
                display_text = "Acquiring your license. Please wait."
            elif message == b"acquired":
                display_text = "License acquired. Thank you."
            else:
                display_text = "License agent error."
            self.updater(display_text)
            sleep(5)


QQuickWindow.setSceneGraphBackend("software")  # legacy fallback

context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect(LICENSEAGENT)

app = QGuiApplication(sys.argv)
engine = QQmlApplicationEngine()
engine.quit.connect(app.quit)
engine.load("./UI/startup.qml")
back_end = Backend()
engine.rootObjects()[0].setProperty("backend", back_end)
back_end.bootUp()
atexit.register(cleanup)
sleep(5)
engine.load("./UI/main.qml")
sys.exit(app.exec())
