from ports import PortScanner
from PySide2 import QtGui, QtCore, QtWidgets
from scapy.all import *
from scanner import Scan
from time import strftime
import win32gui
import win32clipboard
import win32con
import design
import sys

conf.verb = 0  # stops scapy from printing commands


class GUI(design.BaseDesign):
    def __init__(self):
        super().__init__()
        self.setup_ui()

        self.control_keycode = 0x1000021
        self.s_keycode = 0x43
        self.control = False  # if control button was pressed

        self.log = ''
        self.logged = ''
        self.screen = None

        self.progressBar = QtWidgets.QProgressBar()
        self.progressBar.setTextVisible(True)
        self.fred = Scan()

        self.iface = conf.iface

        self.Table.viewport().installEventFilter(self)
        self.run()
        self.canceled = False

    def eventFilter(self, obj, event):
        """
        decide what to do when an event happens
        :param obj: object the event happened on
        :param event: the event that just occurred
        :return: QWidget event filter result
        """
        if event.type() == QtCore.QEvent.MouseButtonPress:
            self.Table.clearSelection()
            self.Table.mousePressEvent(event)

        elif event.type() == QtCore.QEvent.ContextMenu:
            self.contextmenu(event.pos())

        return QtWidgets.QWidget.eventFilter(self, obj, event)

    def change_iface(self, i):
        """
        change current iface
        :param i: index of the selected iface
        """
        if not self.canceled:
            if self.Table.itemAt(0, 0):

                if self.warning_msg():
                    self.start()
                    self.set_iface(i)
                    self.Table.clear()

                else:
                    self.canceled = True
                    self.Ifaces.setCurrentIndex(self.Ifaces.findText(str(self.iface)[1:-40]))

            else:
                self.set_iface(i)

        else:
            self.canceled = False

    @QtCore.Slot()
    def error_msg(self):
        """
        show a critical error message when an interface isn't connected
        Change the stop button text back to start
        """
        QtWidgets.QMessageBox.critical(self, 'Error!',
                                       'The interface selected doesn\'t seem to be connected to a network',
                                       QtWidgets.QMessageBox.Ok)

        self.statusbar.showMessage('Offline')
        self.start()

    def change_status(self, ip, status):
        """
        finds and change status (offline/online)
        :param ip: target ip address
        :param status: new status
        :return: the requested ip object in the table
        """
        it = QtWidgets.QTreeWidgetItemIterator(self.Table)

        while it.value():
            if it.value().text(1) == ip:
                it.value().setText(0, status)
                return it.value()

            it += 1

    @QtCore.Slot(str, str)
    def new(self, ip, status):
        """
        create a new status based on the change
        :param ip: requested ip
        :param status: new status
        """
        QtWidgets.QMessageBox.information(self, 'Network Monitor', '{} has {} the network'.format(ip, status),
                                          QtWidgets.QMessageBox.Ok)
        if status == 'left':
            self.change_status(ip, 'Offline')

    def warning_msg(self):
        """
        shows a warning when content may not be saved
        :return: True if Ok was pressed and False otherwise
        True if ok was pressed
        False if cancel was pressed
        """
        msg = QtWidgets.QMessageBox.warning(self, 'Network Montior', 'All changes made will not be saved',
                                            QtWidgets.QMessageBox.Ok, QtWidgets.QMessageBox.Cancel)

        if msg == QtWidgets.QMessageBox.Ok:  # ok button was pressed
            return True

        return False

    def set_iface(self, index):
        """
        finds and sets the interface to the requested one
        :param index: index of the selected interface
        """
        self.statusbar.showMessage('Ready')
        new_iface = self.Ifaces.itemText(index)
        for iface in IFACES.values():
            if new_iface in str(iface):
                self.iface = iface
                break

    def contextmenu(self, pos):
        """
        opens a context menu
        :param pos: mouse position when clicked
        """
        menu = QtWidgets.QMenu()
        copyaction = menu.addAction('Copy')
        scan = menu.addAction('Scan Host')
        action = menu.exec_(self.Table.viewport().mapToGlobal(pos))

        if action == copyaction:
            self.copy()

        elif action == scan:
            selected = self.Table.selectedItems()
            if selected:
                self.screen = PortScanner(selected[0].text(1))
                self.screen.start()

    def keyPressEvent(self, pressed_key):
        """
        closes the program if esc was pressed
        :param pressed_key: key that was pressed
        """
        if pressed_key.key() == QtCore.Qt.Key_Escape:
            self.close()

        if pressed_key.key() == self.control_keycode:
            self.control = True

        if self.control and pressed_key.key() == self.s_keycode:
            self.copy()
            self.control = False

    @QtCore.Slot(str)
    def add_device(self, package):
        """
        appends a new item to the tree widget
        :param package: pickle object of list of items to add
        """
        new_device = package.split('`')
        item = self.change_status(new_device, 'Online')

        if not item:
            self.fred.ips.append(new_device[1])
            ips = sorted(self.fred.ips, key=lambda ip: list(map(int, ip.split('.'))))   # sort our ips
            i = ips.index(new_device[1])

            item = QtWidgets.QTreeWidgetItem(new_device)

            for device in range(len(new_device)):
                if new_device[device] == 'n\\a':
                    item.setBackground(device, QtGui.QBrush(QtGui.QColor(215, 0, 0)))

            if new_device[-1][:-2].isdigit():
                cr = int(new_device[-1][:-2])

                if cr < 100:
                    col = QtGui.QColor(0, 255 - cr, 0)

                elif cr < 200:
                    col = QtGui.QColor(255 - cr, 0, 0)

                else:
                    col = QtGui.QColor(55, 0, 0)

                item.setBackground(new_device.index(new_device[-1]), QtGui.QBrush(col))

            self.Table.insertTopLevelItem(i, item)

            self.log += '{}({}) is online ({})\n'.format(new_device[1], new_device[3], strftime('%X'))

    @QtCore.Slot(int)
    def loading(self, val):
        """
        sets the progress bar as needed`
        :param val: value needed
        """
        if val == 0:
            self.progressBar.setRange(0, 0)  # sets the progress bar to busy mode

        elif val == 1:
            self.progressBar.setValue(self.progressBar.value() + 1)  # increase current value by one

        else:
            self.progressBar.setMaximum(val)
            self.progressBar.setValue(0)

            self.log += 'Initial scan has been activated on {}({})\n'.format(self.Ifaces.currentText(),
                                                                             time.strftime('%X'))

    def copy(self):
        """
        copies the selected text over to the clipboard
        """
        selected = self.Table.selectedItems()
        if selected:
            txt = selected[0].text(1)
            win32clipboard.OpenClipboard()

            win32clipboard.SetClipboardData(1, txt)
            win32clipboard.SetClipboardData(7, txt)
            win32clipboard.SetClipboardData(13, txt.decode('utf-8'))

            win32clipboard.CloseClipboard()
            self.Table.clearSelection()
            self.Table.clearFocus()

    @QtCore.Slot()
    def done(self):
        """
        called when the scan is done
        sets the text on the button to start
        sets the progress back to normal mode
        """
        self.Start.setText('Start')
        self.progressBar.setRange(0, 1)

        self.log += 'The scan was canceled by the user({})\n'.format(time.strftime('%X'))

    def save(self):
        """
        saves scan results
        """
        filter = 'Log files (*.log)\0*.log\0All files (*.*)\0*.*\0'
        customfilter = 'Other file types\0*.*\0'
        fname = None

        try:
            fname, customfilter, flags = win32gui.GetSaveFileNameW(
                InitialDir='C:\\',
                Flags=win32con.OFN_ALLOWMULTISELECT | win32con.OFN_EXPLORER,
                File='', DefExt='log',
                Title='Save File',
                Filter=filter,
                CustomFilter=customfilter,
                FilterIndex=1)

        except:
            pass

        if fname:
            with open(fname, 'w') as f:
                f.write(self.log)

            self.logged = self.log

    def connection(self):
        """
        connect our fred to all the different functions
        """
        self.fred.status.connect(self.show_msg)
        self.fred.finished.connect(self.done)
        self.fred.prog.connect(self.loading)
        self.fred.error.connect(self.error_msg)
        self.fred.device.connect(self.add_device)
        self.fred.new_device.connect(self.new)

    @QtCore.Slot(str)
    def show_msg(self, msg):
        """
        show the message on the status bar
        :param msg: the message to show
        """
        self.statusbar.showMessage(msg)

    def start(self):
        """
        starts/stops the scan thread
        """
        if self.Start.text() == 'Start':

            if self.statusbar.currentMessage() == 'Offline Interface':
                self.statusbar.showMessage('Ready')
                return

            self.Start.setText('Stop')

            conf.iface = self.iface
            self.fred = Scan()
            self.connection()

            self.fred.start()

        else:

            if self.Table.itemAt(0, 0):

                if self.warning_msg():
                    self.Table.clear()

                else:
                    return

            if self.fred.isRunning():
                self.fred.terminate()

            self.Start.setText('Start')

            self.statusbar.showMessage('Offline Interface')

    def run(self):
        """
        sets all the necessary adjustments to start the program
        """
        for iface in ifaces.data.values():
            self.Ifaces.addItem(iface.name)

        self.Ifaces.setCurrentText(self.iface.name)

        self.Table.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Start.clicked.connect(self.start)
        self.Ifaces.currentIndexChanged.connect(self.set_iface)
        self.actionExit.triggered.connect(lambda: self.close())
        self.actionSave.triggered.connect(self.save)
        self.actionSave.setShortcut(QtGui.QKeySequence.Save)

        header = self.Table.header()
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(6, QtWidgets.QHeaderView.ResizeToContents)
        header.setStretchLastSection(False)

        self.statusbar.insertPermanentWidget(0, self.progressBar)
        self.statusbar.showMessage('Ready')

    def closeEvent(self, event):
        """
        triggered when user tries to close the program
        if a scan is running shows an warning message
        :param event: close event
        """
        if self.Table.itemAt(0, 0):
            if self.logged != self.log:
                if not self.warning_msg():  # if cancel was pressed abort the exiting
                    event.ignore()
                    return

        if self.fred.isRunning():
            self.fred.terminate()

        sys.exit(0)


def main():
    """
    main function
    """
    app = QtWidgets.QApplication(sys.argv)
    form = GUI()
    form.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
