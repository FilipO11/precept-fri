import sys, os, threading, zmq, subprocess, atexit
from time import sleep
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtQml import QQmlApplicationEngine
from PyQt6.QtQuick import QQuickWindow
from PyQt6.QtCore import QObject, pyqtSignal

LICENSEAGENT = "tcp://localhost:8100"

def cleanup():
    laproc.kill()

class Backend(QObject):
    def __init__(self):
        QObject.__init__(self)
    updated = pyqtSignal(str, arguments=['updater'])
    def updater(self, curr_time):
        self.updated.emit(curr_time)
    def bootUp(self):
        # subprocess.Popen(['C:/Python312/python.exe', './LicenseAgent.exe'])
        global laproc
        laproc = subprocess.Popen(['C:/Python312/python.exe', './LicenseAgent.py'], stdout="lalogs.txt")
        t_thread = threading.Thread(target=self._bootUp)
        t_thread.daemon = True
        t_thread.start()
    def _bootUp(self):
        socket.send(b"liccheck")
        message = socket.recv()
        self.updater(message.decode("utf-8"))
        

QQuickWindow.setSceneGraphBackend('software') # legacy fallback

context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect(LICENSEAGENT)

app = QGuiApplication(sys.argv)
engine = QQmlApplicationEngine()
engine.quit.connect(app.quit)
engine.load('./UI/app.qml')
atexit.register(cleanup)
back_end = Backend()
engine.rootObjects()[0].setProperty('backend', back_end)
back_end.bootUp()
sys.exit(app.exec())
