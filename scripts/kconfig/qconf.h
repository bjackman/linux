/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 */

#include <QCheckBox>
#include <QDialog>
#include <QHeaderView>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QSettings>
#include <QSplitter>
#include <QStyledItemDelegate>
#include <QTextBrowser>
#include <QTreeWidget>
#include <QTableWidget>
#include <QList>
#include <QComboBox>
#include <QVBoxLayout>
#include <QLabel>
#include <thread>
#include <condition_variable>

#include "expr.h"
#include "cf_defs.h"


class ConfigList;
class ConfigItem;
class ConfigMainWindow;

class ConfigSettings : public QSettings {
public:
	ConfigSettings();
	QList<int> readSizes(const QString& key, bool *ok);
	bool writeSizes(const QString& key, const QList<int>& value);
};

enum colIdx {
	promptColIdx, nameColIdx, dataColIdx
};
enum listMode {
	singleMode, menuMode, symbolMode, fullMode, listMode
};
enum optionMode {
	normalOpt = 0, allOpt, promptOpt
};

class ConfigList : public QTreeWidget {
	Q_OBJECT
	typedef class QTreeWidget Parent;
public:
	ConfigList(QWidget *parent, const char *name = 0);
	~ConfigList();
	void reinit(void);
	ConfigItem* findConfigItem(struct menu *);
	void setSelected(QTreeWidgetItem *item, bool enable) {
		for (int i = 0; i < selectedItems().size(); i++)
			selectedItems().at(i)->setSelected(false);

		item->setSelected(enable);
	}

protected:
	void keyPressEvent(QKeyEvent *e);
	void mouseReleaseEvent(QMouseEvent *e);
	void mouseDoubleClickEvent(QMouseEvent *e);
	void focusInEvent(QFocusEvent *e);
	void contextMenuEvent(QContextMenuEvent *e);

public slots:
	void setRootMenu(struct menu *menu);

	void updateList();
	void setValue(ConfigItem* item, tristate val);
	void changeValue(ConfigItem* item);
	void updateSelection(void);
	void saveSettings(void);
	void setOptionMode(QAction *action);
	void setShowName(bool on);

signals:
	void menuChanged(struct menu *menu);
	void menuSelected(struct menu *menu);
	void itemSelected(struct menu *menu);
	void parentSelected(void);
	void gotFocus(struct menu *);
	void showNameChanged(bool on);
	void selectionChanged(QList<QTreeWidgetItem *> selection);
	void updateConflictsViewColorization();

public:
	void updateListAll(void)
	{
		updateAll = true;
		updateList();
		updateAll = false;
	}
	void setAllOpen(bool open);
	void setParentMenu(void);

	bool menuSkip(struct menu *);

	void updateMenuList(ConfigItem *parent, struct menu*);
	void updateMenuList(struct menu *menu);

	bool updateAll;

	bool showName;
	enum listMode mode;
	enum optionMode optMode;
	struct menu *rootEntry;
	QPalette disabledColorGroup;
	QPalette inactivedColorGroup;
	QMenu* headerPopup;

	static QList<ConfigList *> allLists;
	static void updateListForAll();
	static void updateListAllForAll();

	static QAction *showNormalAction, *showAllAction, *showPromptAction;
	static QAction *addSymbolFromContextMenu;

};

class ConflictsView : public QWidget {
	Q_OBJECT
	typedef class QWidget Parent;
private:
	QAction *loadingAction;
public:
	ConflictsView(QWidget *parent, const char *name = 0);
	~ConflictsView(void);
	void addSymbolFromMenu(struct menu *m);
	int current_solution_number = -1;

public slots:
	void cellClicked(int, int);
	void changeAll();
	// triggered by Qactions on the tool bar that adds/remove symbol
	void addSymbol();
	// triggered from config list right click -> add symbols
	void addSymbolFromContextMenu();
	void removeSymbol();
	void menuChanged(struct menu *);
	void changeToNo();
	void changeToYes();
	void changeToModule();
	void selectionChanged(QList<QTreeWidgetItem *> selection);

	void applyFixButtonClick();
	void updateConflictsViewColorization();
	void updateResults();

	// switches the solution table with selected solution index from  solution_output
	void changeSolutionTable(int solution_number);

	// calls satconfig to solve to get wanted value to current value
	void calculateFixes();
signals:
	void showNameChanged(bool);
	void showRangeChanged(bool);
	void showDataChanged(bool);
	void conflictSelected(struct menu *);
	void refreshMenu();
	void resultsReady();
public:
	QTableWidget *conflictsTable;

	// the comobox on the right hand side. used to select a solution after
	// getting solution from satconfig
	QComboBox *solutionSelector{nullptr};

	// the table which shows the selected solution showing variable = New value changes
	QTableWidget *solutionTable{nullptr};

	// Apply fixes button on the solution view
	QPushButton *applyFixButton{nullptr};

	struct sfix_list **solution_output{nullptr};
	size_t num_solutions;

	QToolBar *conflictsToolBar;
	struct menu *currentSelectedMenu;
	QLabel *numSolutionLabel{nullptr};
	// currently selected config items in configlist.
	QList<QTreeWidgetItem *> currentSelection;
	QAction *fixConflictsAction_{nullptr};
	void runSatConfAsync();
	std::thread *runSatConfAsyncThread{nullptr};

	std::mutex satconf_mutex;
	std::condition_variable satconf_cancellation_cv;
	bool satconf_cancelled{false};

private:
	void addPicoSatNote(QToolBar &layout);
};

class ConfigItem : public QTreeWidgetItem {
	typedef class QTreeWidgetItem Parent;
public:
	ConfigItem(ConfigList *parent, ConfigItem *after, struct menu *m)
	: Parent(parent, after), nextItem(0), menu(m), goParent(false)
	{
		init();
	}
	ConfigItem(ConfigItem *parent, ConfigItem *after, struct menu *m)
	: Parent(parent, after), nextItem(0), menu(m), goParent(false)
	{
		init();
	}
	ConfigItem(ConfigList *parent, ConfigItem *after)
	: Parent(parent, after), nextItem(0), menu(0), goParent(true)
	{
		init();
	}
	~ConfigItem(void);
	void init(void);
	void updateMenu(void);
	void testUpdateMenu(void);
	ConfigList* listView() const
	{
		return (ConfigList*)Parent::treeWidget();
	}
	ConfigItem* firstChild() const
	{
		return (ConfigItem *)Parent::child(0);
	}
	ConfigItem* nextSibling()
	{
		ConfigItem *ret = NULL;
		ConfigItem *_parent = (ConfigItem *)parent();

		if(_parent) {
			ret = (ConfigItem *)_parent->child(_parent->indexOfChild(this)+1);
		} else {
			QTreeWidget *_treeWidget = treeWidget();
			ret = (ConfigItem *)_treeWidget->topLevelItem(_treeWidget->indexOfTopLevelItem(this)+1);
		}

		return ret;
	}
	// TODO: Implement paintCell

	ConfigItem* nextItem;
	struct menu *menu;
	bool goParent;

	static QIcon symbolYesIcon, symbolModIcon, symbolNoIcon;
	static QIcon choiceYesIcon, choiceNoIcon;
	static QIcon menuIcon, menubackIcon;
};

class ConfigItemDelegate : public QStyledItemDelegate
{
private:
	struct menu *menu;
public:
	ConfigItemDelegate(QObject *parent = nullptr)
		: QStyledItemDelegate(parent) {}
	QWidget *createEditor(QWidget *parent,
			      const QStyleOptionViewItem &option,
			      const QModelIndex &index) const override;
	void setModelData(QWidget *editor, QAbstractItemModel *model,
			  const QModelIndex &index) const override;
};

class ConfigInfoView : public QTextBrowser {
	Q_OBJECT
	typedef class QTextBrowser Parent;
	QMenu *contextMenu;
public:
	ConfigInfoView(QWidget* parent, const char *name = 0);
	bool showDebug(void) const { return _showDebug; }

public slots:
	void setInfo(struct menu *menu);
	void saveSettings(void);
	void setShowDebug(bool);
	void clicked (const QUrl &url);

signals:
	void showDebugChanged(bool);
	void menuSelected(struct menu *);

protected:
	void symbolInfo(void);
	void menuInfo(void);
	QString debug_info(struct symbol *sym);
	static QString print_filter(const QString &str);
	static void expr_print_help(void *data, struct symbol *sym, const char *str);
	void contextMenuEvent(QContextMenuEvent *event);

	struct symbol *sym;
	struct menu *_menu;
	bool _showDebug;
};

class PicoSATInstallInfoWindow : public QDialog {
	Q_OBJECT
public:
	PicoSATInstallInfoWindow(QWidget *parent);
};

class ConfigSearchWindow : public QDialog {
	Q_OBJECT
	typedef class QDialog Parent;
public:
	ConfigSearchWindow(ConfigMainWindow *parent);

public slots:
	void saveSettings(void);
	void search(void);
	void updateConflictsViewColorizationFowarder();
signals:
	void updateConflictsViewColorization();

protected:
	QLineEdit* editField;
	QPushButton* searchButton;
	QSplitter* split;
	ConfigList *list;
	ConfigInfoView* info;

	struct symbol **result;
};

class ConfigMainWindow : public QMainWindow {
	Q_OBJECT

	QString configname;
	static QAction *saveAction;
	static void conf_changed(bool);
public:
	ConfigMainWindow(void);
public slots:
	void changeMenu(struct menu *);
	void changeItens(struct menu *);
	void setMenuLink(struct menu *);
	void listFocusChanged(void);
	void goBack(void);
	void loadConfig(void);
	bool saveConfig(void);
	void saveConfigAs(void);
	void searchConfig(void);
	void showSingleView(void);
	void showSplitView(void);
	void showFullView(void);
	void showIntro(void);
	void showAbout(void);
	void saveSettings(void);
	void conflictSelected(struct menu *);
	void refreshMenu();

protected:
	void closeEvent(QCloseEvent *e);

	ConfigSearchWindow *searchWindow;
	ConfigList *menuList;
	ConfigList *configList;
	ConfigInfoView *helpText;
	ConflictsView *conflictsView;
	QToolBar *conflictsToolBar;
	QAction *backAction;
	QAction *singleViewAction;
	QAction *splitViewAction;
	QAction *fullViewAction;
	QSplitter *split1;
	QSplitter *split2;
	QSplitter *split3;
};

class dropAbleView : public QTableWidget
{
public:
	dropAbleView(QWidget *parent = nullptr);
	~dropAbleView();

protected:
	void dropEvent(QDropEvent *event);
};
