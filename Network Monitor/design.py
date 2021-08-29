from PySide2 import QtCore, QtWidgets


class BaseDesign(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.centralwidget = QtWidgets.QWidget(self)

        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.Table = QtWidgets.QTreeWidget(self.centralwidget)
        self.Start = QtWidgets.QPushButton(self.centralwidget)
        self.Ifaces = QtWidgets.QComboBox(self.centralwidget)
        self.Iface = QtWidgets.QLabel(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(self)
        self.actionSave = QtWidgets.QAction(self)
        self.actionAbout = QtWidgets.QAction(self)
        self.actionExit = QtWidgets.QAction(self)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.menuStyle = QtWidgets.QMenu(self.menubar)
        self.menuView = QtWidgets.QMenu(self.menubar)
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuFile = QtWidgets.QMenu(self.menubar)

    def setup_ui(self):
        self.setEnabled(True)
        self.resize(850, 546)
        self.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.setWindowTitle('Network Monitor')

        size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        size_policy.setHorizontalStretch(0)
        size_policy.setVerticalStretch(0)
        size_policy.setHeightForWidth(self.Ifaces.sizePolicy().hasHeightForWidth())

        self.Ifaces.setSizePolicy(size_policy)
        self.Ifaces.setMinimumSize(QtCore.QSize(225, 0))
        self.gridLayout.addWidget(self.Ifaces, 0, 1, 1, 1)

        size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        size_policy.setHorizontalStretch(0)
        size_policy.setVerticalStretch(0)
        size_policy.setHeightForWidth(self.Iface.sizePolicy().hasHeightForWidth())
        self.Iface.setSizePolicy(size_policy)
        self.gridLayout.addWidget(self.Iface, 0, 0, 1, 1)
        self.gridLayout.addWidget(self.Start, 0, 2, 1, 1, QtCore.Qt.AlignRight)
        self.Table.setIndentation(0)
        self.Table.header().setDefaultSectionSize(135)
        self.Table.header().setStretchLastSection(False)
        self.gridLayout.addWidget(self.Table, 1, 0, 1, 3)
        self.setCentralWidget(self.centralwidget)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 833, 21))
        self.setMenuBar(self.menubar)

        self.setStatusBar(self.statusbar)
        self.menuFile.addAction(self.actionSave)
        self.menuFile.addSeparator()

        self.menuFile.addAction(self.actionExit)
        self.menuHelp.addAction(self.actionAbout)

        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())

        self.setTabOrder(self.Ifaces, self.Start)

        self.add_text()

    def add_text(self):
        self.Iface.setText('Iface')
        self.Start.setText('Start')

        self.Table.headerItem().setText(0, 'Status')
        self.Table.headerItem().setText(1, 'IP')
        self.Table.headerItem().setText(2, 'Name')
        self.Table.headerItem().setText(3, 'Mac Address')
        self.Table.headerItem().setText(4, 'Manufacturer')
        self.Table.headerItem().setText(5, 'OS')
        self.Table.headerItem().setText(6, 'Ping')

        self.menuFile.setTitle('File')
        self.menuHelp.setTitle('Help')
        self.menuView.setTitle('View')
        self.menuStyle.setTitle('Themes')

        self.actionExit.setText('Exit')
        self.actionAbout.setText('About...')
        self.actionSave.setText('Save')
