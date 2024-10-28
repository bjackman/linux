// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 * Copyright (C) 2015 Boris Barbulovski <bbarbulovski@gmail.com>
 */

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QCloseEvent>
#include <QDebug>
#include <QFileDialog>
#include <QLabel>
#include <QLayout>
#include <QList>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QRegularExpression>
#include <QScreen>
#include <QToolBar>
#include <QListWidget>
#include <QComboBox>
#include <QTableWidget>
#include <QHBoxLayout>
#include <QMovie>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QAbstractItemView>
#include <QMimeData>
#include <QBrush>
#include <QColor>

#include <xalloc.h>
#include "lkc.h"
#include <vector>
#include <stdlib.h>

#include "lkc.h"
#include "qconf.h"
#include "configfix.h"
#include "picosat_functions.h"

#include "images.h"

static QString tristate_value_to_string(tristate val);
static tristate string_value_to_tristate(QString s);

static QApplication *configApp;
static ConfigSettings *configSettings;

QAction *ConfigMainWindow::saveAction;

static bool picosat_available;

ConfigSettings::ConfigSettings()
	: QSettings("kernel.org", "qconf")
{
}

/**
 * Reads a list of integer values from the application settings.
 */
QList<int> ConfigSettings::readSizes(const QString& key, bool *ok)
{
	QList<int> result;

	if (contains(key))
	{
		QStringList entryList = value(key).toStringList();
		QStringList::Iterator it;

		for (it = entryList.begin(); it != entryList.end(); ++it)
			result.push_back((*it).toInt());

		*ok = true;
	}
	else
		*ok = false;

	return result;
}

/**
 * Writes a list of integer values to the application settings.
 */
bool ConfigSettings::writeSizes(const QString& key, const QList<int>& value)
{
	QStringList stringList;
	QList<int>::ConstIterator it;

	for (it = value.begin(); it != value.end(); ++it)
		stringList.push_back(QString::number(*it));
	setValue(key, stringList);

	return true;
}

QIcon ConfigItem::symbolYesIcon;
QIcon ConfigItem::symbolModIcon;
QIcon ConfigItem::symbolNoIcon;
QIcon ConfigItem::choiceYesIcon;
QIcon ConfigItem::choiceNoIcon;
QIcon ConfigItem::menuIcon;
QIcon ConfigItem::menubackIcon;

/*
 * update the displayed of a menu entry
 */
void ConfigItem::updateMenu(void)
{
	ConfigList* list;
	struct symbol* sym;
	struct property *prop;
	QString prompt;
	int type;
	tristate expr;

	list = listView();
	if (goParent) {
		setIcon(promptColIdx, menubackIcon);
		prompt = "..";
		goto set_prompt;
	}

	sym = menu->sym;
	prop = menu->prompt;
	prompt = menu_get_prompt(menu);

	if (prop) switch (prop->type) {
	case P_MENU:
		if (list->mode == singleMode) {
			/* a menuconfig entry is displayed differently
			 * depending whether it's at the view root or a child.
			 */
			if (sym && list->rootEntry == menu)
				break;
			setIcon(promptColIdx, menuIcon);
		} else {
			if (sym)
				break;
			setIcon(promptColIdx, QIcon());
		}
		goto set_prompt;
	case P_COMMENT:
		setIcon(promptColIdx, QIcon());
		prompt = "*** " + prompt + " ***";
		goto set_prompt;
	default:
		;
	}
	if (!sym)
		goto set_prompt;

	setText(nameColIdx, sym->name);

	type = sym_get_type(sym);
	switch (type) {
	case S_BOOLEAN:
	case S_TRISTATE:
		char ch;

		if (!sym_is_changeable(sym) && list->optMode == normalOpt) {
			setIcon(promptColIdx, QIcon());
			break;
		}
		expr = sym_get_tristate_value(sym);
		switch (expr) {
		case yes:
			if (sym_is_choice_value(sym))
				setIcon(promptColIdx, choiceYesIcon);
			else
				setIcon(promptColIdx, symbolYesIcon);
			ch = 'Y';
			break;
		case mod:
			setIcon(promptColIdx, symbolModIcon);
			ch = 'M';
			break;
		default:
			if (sym_is_choice_value(sym))
				setIcon(promptColIdx, choiceNoIcon);
			else
				setIcon(promptColIdx, symbolNoIcon);
			ch = 'N';
			break;
		}

		setText(dataColIdx, QChar(ch));
		break;
	case S_INT:
	case S_HEX:
	case S_STRING:
		setText(dataColIdx, sym_get_string_value(sym));
		break;
	}
	if (!sym_has_value(sym))
		prompt += " (NEW)";
set_prompt:
	setText(promptColIdx, prompt);
}

void ConfigItem::testUpdateMenu(void)
{
	ConfigItem* i;

	if (!menu)
		return;

	sym_calc_value(menu->sym);
	if (menu->flags & MENU_CHANGED) {
		/* the menu entry changed, so update all list items */
		menu->flags &= ~MENU_CHANGED;
		for (i = (ConfigItem*)menu->data; i; i = i->nextItem)
			i->updateMenu();
	} else if (listView()->updateAll)
		updateMenu();
}


/*
 * construct a menu entry
 */
void ConfigItem::init(void)
{
	if (menu) {
		ConfigList* list = listView();
		nextItem = (ConfigItem*)menu->data;
		menu->data = this;

		if (list->mode != fullMode)
			setExpanded(true);
		sym_calc_value(menu->sym);

		if (menu->sym) {
			enum symbol_type type = menu->sym->type;

			// Allow to edit "int", "hex", and "string" in-place in
			// the data column. Unfortunately, you cannot specify
			// the flags per column. Set ItemIsEditable for all
			// columns here, and check the column in createEditor().
			if (type == S_INT || type == S_HEX || type == S_STRING)
				setFlags(flags() | Qt::ItemIsEditable);
		}
	}
	updateMenu();
}

/*
 * destruct a menu entry
 */
ConfigItem::~ConfigItem(void)
{
	if (menu) {
		ConfigItem** ip = (ConfigItem**)&menu->data;
		for (; *ip; ip = &(*ip)->nextItem) {
			if (*ip == this) {
				*ip = nextItem;
				break;
			}
		}
	}
}

QWidget *ConfigItemDelegate::createEditor(QWidget *parent,
					  const QStyleOptionViewItem &option,
					  const QModelIndex &index) const
{
	ConfigItem *item;

	// Only the data column is editable
	if (index.column() != dataColIdx)
		return nullptr;

	// You cannot edit invisible menus
	item = static_cast<ConfigItem *>(index.internalPointer());
	if (!item || !item->menu || !menu_is_visible(item->menu))
		return nullptr;

	return QStyledItemDelegate::createEditor(parent, option, index);
}

void ConfigItemDelegate::setModelData(QWidget *editor,
				      QAbstractItemModel *model,
				      const QModelIndex &index) const
{
	QLineEdit *lineEdit;
	ConfigItem *item;
	struct symbol *sym;
	bool success;

	lineEdit = qobject_cast<QLineEdit *>(editor);
	// If this is not a QLineEdit, use the parent's default.
	// (does this happen?)
	if (!lineEdit)
		goto parent;

	item = static_cast<ConfigItem *>(index.internalPointer());
	if (!item || !item->menu)
		goto parent;

	sym = item->menu->sym;
	if (!sym)
		goto parent;

	success = sym_set_string_value(sym, lineEdit->text().toUtf8().data());
	if (success) {
		ConfigList::updateListForAll();
	} else {
		QMessageBox::information(editor, "qconf",
			"Cannot set the data (maybe due to out of range).\n"
			"Setting the old value.");
		lineEdit->setText(sym_get_string_value(sym));
	}

parent:
	QStyledItemDelegate::setModelData(editor, model, index);
}

ConfigList::ConfigList(QWidget *parent, const char *name)
	: QTreeWidget(parent),
	  updateAll(false),
	  showName(false), mode(singleMode), optMode(normalOpt),
	  rootEntry(0), headerPopup(0)
{
	setObjectName(name);
	setSortingEnabled(false);

	setVerticalScrollMode(ScrollPerPixel);
	setHorizontalScrollMode(ScrollPerPixel);

	setHeaderLabels(QStringList() << "Option" << "Name" << "Value");

	connect(this, &ConfigList::itemSelectionChanged,
		this, &ConfigList::updateSelection);

	if (name) {
		configSettings->beginGroup(name);
		showName = configSettings->value("/showName", false).toBool();
		optMode = (enum optionMode)configSettings->value("/optionMode", 0).toInt();
		configSettings->endGroup();
		connect(configApp, &QApplication::aboutToQuit,
			this, &ConfigList::saveSettings);
	}

	showColumn(promptColIdx);

	setItemDelegate(new ConfigItemDelegate(this));

	allLists.append(this);

	reinit();
}

ConfigList::~ConfigList()
{
	allLists.removeOne(this);
}

bool ConfigList::menuSkip(struct menu *menu)
{
	if (optMode == normalOpt && menu_is_visible(menu))
		return false;
	if (optMode == promptOpt && menu_has_prompt(menu))
		return false;
	if (optMode == allOpt)
		return false;
	return true;
}

void ConfigList::reinit(void)
{
	hideColumn(nameColIdx);

	if (showName)
		showColumn(nameColIdx);

	updateListAll();
}

void ConfigList::setOptionMode(QAction *action)
{
	if (action == showNormalAction)
		optMode = normalOpt;
	else if (action == showAllAction)
		optMode = allOpt;
	else
		optMode = promptOpt;

	updateListAll();
}

void ConfigList::saveSettings(void)
{
	if (!objectName().isEmpty()) {
		configSettings->beginGroup(objectName());
		configSettings->setValue("/showName", showName);
		configSettings->setValue("/optionMode", (int)optMode);
		configSettings->endGroup();
	}
}

ConfigItem* ConfigList::findConfigItem(struct menu *menu)
{
	ConfigItem* item = (ConfigItem*)menu->data;

	for (; item; item = item->nextItem) {
		if (this == item->listView())
			break;
	}

	return item;
}

void ConfigList::updateSelection(void)
{
	struct menu *menu;
	enum prop_type type;

	if (selectedItems().count() == 0)
		return;

	ConfigItem* item = (ConfigItem*)selectedItems().first();
	if (!item)
		return;
	emit selectionChanged(selectedItems());
	menu = item->menu;
	emit menuChanged(menu);
	if (!menu)
		return;
	type = menu->prompt ? menu->prompt->type : P_UNKNOWN;
	if (mode == menuMode && type == P_MENU)
		emit menuSelected(menu);
}

void ConfigList::updateList()
{
	ConfigItem* last = 0;
	ConfigItem *item;

	if (!rootEntry) {
		if (mode != listMode)
			goto update;
		QTreeWidgetItemIterator it(this);

		while (*it) {
			item = (ConfigItem*)(*it);
			if (!item->menu)
				continue;
			item->testUpdateMenu();

			++it;
		}
		return;
	}

	if (rootEntry != &rootmenu && mode == singleMode) {
		item = (ConfigItem *)topLevelItem(0);
		if (!item)
			item = new ConfigItem(this, 0);
		last = item;
	}
	if ((mode == singleMode || (mode == symbolMode && !(rootEntry->flags & MENU_ROOT))) &&
	    rootEntry->sym && rootEntry->prompt) {
		item = last ? last->nextSibling() : nullptr;
		if (!item)
			item = new ConfigItem(this, last, rootEntry);
		else
			item->testUpdateMenu();

		updateMenuList(item, rootEntry);
		update();
		resizeColumnToContents(0);
		return;
	}
update:
	updateMenuList(rootEntry);
	update();
	resizeColumnToContents(0);
}

void ConfigList::updateListForAll()
{
	QListIterator<ConfigList *> it(allLists);

	while (it.hasNext()) {
		ConfigList *list = it.next();

		list->updateList();
	}
}

void ConfigList::updateListAllForAll()
{
	QListIterator<ConfigList *> it(allLists);

	while (it.hasNext()) {
		ConfigList *list = it.next();

		list->updateList();
	}
}

void ConfigList::setValue(ConfigItem* item, tristate val)
{
	struct symbol* sym;
	int type;
	tristate oldval;

	sym = item->menu ? item->menu->sym : 0;
	if (!sym)
		return;

	type = sym_get_type(sym);
	switch (type) {
	case S_BOOLEAN:
	case S_TRISTATE:
		oldval = sym_get_tristate_value(sym);

		if (!sym_set_tristate_value(sym, val))
			return;
		if (oldval == no && item->menu->list)
			item->setExpanded(true);
		ConfigList::updateListForAll();
		break;
	}
}

void ConfigList::changeValue(ConfigItem* item)
{
	struct symbol* sym;
	struct menu* menu;
	int type, oldexpr, newexpr;

	menu = item->menu;
	if (!menu)
		return;
	sym = menu->sym;
	if (!sym) {
		if (item->menu->list)
			item->setExpanded(!item->isExpanded());
		return;
	}

	type = sym_get_type(sym);
	switch (type) {
	case S_BOOLEAN:
	case S_TRISTATE:
		oldexpr = sym_get_tristate_value(sym);
		newexpr = sym_toggle_tristate_value(sym);
		if (item->menu->list) {
			if (oldexpr == newexpr)
				item->setExpanded(!item->isExpanded());
			else if (oldexpr == no)
				item->setExpanded(true);
		}
		if (oldexpr != newexpr)
			ConfigList::updateListForAll();
			emit updateConflictsViewColorization();
		break;
	default:
		break;
	}
}

void ConfigList::setRootMenu(struct menu *menu)
{
	enum prop_type type;

	if (rootEntry == menu)
		return;
	type = menu && menu->prompt ? menu->prompt->type : P_UNKNOWN;
	if (type != P_MENU)
		return;
	updateMenuList(0);
	rootEntry = menu;
	updateListAll();
	if (currentItem()) {
		setSelected(currentItem(), hasFocus());
		scrollToItem(currentItem());
	}
}

void ConfigList::setParentMenu(void)
{
	ConfigItem* item;
	struct menu *oldroot;

	oldroot = rootEntry;
	if (rootEntry == &rootmenu)
		return;
	setRootMenu(menu_get_parent_menu(rootEntry->parent));

	QTreeWidgetItemIterator it(this);
	while (*it) {
		item = (ConfigItem *)(*it);
		if (item->menu == oldroot) {
			setCurrentItem(item);
			scrollToItem(item);
			break;
		}

		++it;
	}
}

/*
 * update all the children of a menu entry
 *   removes/adds the entries from the parent widget as necessary
 *
 * parent: either the menu list widget or a menu entry widget
 * menu: entry to be updated
 */
void ConfigList::updateMenuList(ConfigItem *parent, struct menu* menu)
{
	struct menu* child;
	ConfigItem* item;
	ConfigItem* last;
	enum prop_type type;

	if (!menu) {
		while (parent->childCount() > 0)
		{
			delete parent->takeChild(0);
		}

		return;
	}

	last = parent->firstChild();
	if (last && !last->goParent)
		last = 0;
	for (child = menu->list; child; child = child->next) {
		item = last ? last->nextSibling() : parent->firstChild();
		type = child->prompt ? child->prompt->type : P_UNKNOWN;

		switch (mode) {
		case menuMode:
			if (!(child->flags & MENU_ROOT))
				goto hide;
			break;
		case symbolMode:
			if (child->flags & MENU_ROOT)
				goto hide;
			break;
		default:
			break;
		}

		if (!menuSkip(child)) {
			if (!child->sym && !child->list && !child->prompt)
				continue;
			if (!item || item->menu != child)
				item = new ConfigItem(parent, last, child);
			else
				item->testUpdateMenu();

			if (mode == fullMode || mode == menuMode || type != P_MENU)
				updateMenuList(item, child);
			else
				updateMenuList(item, 0);
			last = item;
			continue;
		}
hide:
		if (item && item->menu == child) {
			last = parent->firstChild();
			if (last == item)
				last = 0;
			else while (last->nextSibling() != item)
				last = last->nextSibling();
			delete item;
		}
	}
}

void ConfigList::updateMenuList(struct menu *menu)
{
	struct menu* child;
	ConfigItem* item;
	ConfigItem* last;
	enum prop_type type;

	if (!menu) {
		while (topLevelItemCount() > 0)
		{
			delete takeTopLevelItem(0);
		}

		return;
	}

	last = (ConfigItem *)topLevelItem(0);
	if (last && !last->goParent)
		last = 0;
	for (child = menu->list; child; child = child->next) {
		item = last ? last->nextSibling() : (ConfigItem *)topLevelItem(0);
		type = child->prompt ? child->prompt->type : P_UNKNOWN;

		switch (mode) {
		case menuMode:
			if (!(child->flags & MENU_ROOT))
				goto hide;
			break;
		case symbolMode:
			if (child->flags & MENU_ROOT)
				goto hide;
			break;
		default:
			break;
		}

		if (!menuSkip(child)) {
			if (!child->sym && !child->list && !child->prompt)
				continue;
			if (!item || item->menu != child)
				item = new ConfigItem(this, last, child);
			else
				item->testUpdateMenu();

			if (mode == fullMode || mode == menuMode || type != P_MENU)
				updateMenuList(item, child);
			else
				updateMenuList(item, 0);
			last = item;
			continue;
		}
hide:
		if (item && item->menu == child) {
			last = (ConfigItem *)topLevelItem(0);
			if (last == item)
				last = 0;
			else while (last->nextSibling() != item)
				last = last->nextSibling();
			delete item;
		}
	}
}

void ConfigList::keyPressEvent(QKeyEvent* ev)
{
	QTreeWidgetItem* i = currentItem();
	ConfigItem* item;
	struct menu *menu;
	enum prop_type type;

	if (ev->key() == Qt::Key_Escape && mode == singleMode) {
		emit parentSelected();
		ev->accept();
		return;
	}

	if (!i) {
		Parent::keyPressEvent(ev);
		return;
	}
	item = (ConfigItem*)i;

	switch (ev->key()) {
	case Qt::Key_Return:
	case Qt::Key_Enter:
		if (item->goParent) {
			emit parentSelected();
			break;
		}
		menu = item->menu;
		if (!menu)
			break;
		type = menu->prompt ? menu->prompt->type : P_UNKNOWN;
		if (type == P_MENU && rootEntry != menu &&
		    mode != fullMode && mode != menuMode) {
			if (mode == menuMode)
				emit menuSelected(menu);
			else
				emit itemSelected(menu);
			break;
		}
	case Qt::Key_Space:
		changeValue(item);
		break;
	case Qt::Key_N:
		setValue(item, no);
		break;
	case Qt::Key_M:
		setValue(item, mod);
		break;
	case Qt::Key_Y:
		setValue(item, yes);
		break;
	default:
		Parent::keyPressEvent(ev);
		return;
	}
	ev->accept();
}

void ConfigList::mouseReleaseEvent(QMouseEvent* e)
{
	QPoint p = e->pos();
	ConfigItem* item = (ConfigItem*)itemAt(p);
	struct menu *menu;
	enum prop_type ptype;
	QIcon icon;
	int idx, x;

	if (!item)
		goto skip;

	menu = item->menu;
	x = header()->offset() + p.x();
	idx = header()->logicalIndexAt(x);
	switch (idx) {
	case promptColIdx:
		icon = item->icon(promptColIdx);
		if (!icon.isNull()) {
			int off = header()->sectionPosition(0) + visualRect(indexAt(p)).x() + 4; // 4 is Hardcoded image offset. There might be a way to do it properly.
			if (x >= off && x < off + icon.availableSizes().first().width()) {
				if (item->goParent) {
					emit parentSelected();
					break;
				} else if (!menu)
					break;
				ptype = menu->prompt ? menu->prompt->type : P_UNKNOWN;
				if (ptype == P_MENU && rootEntry != menu &&
				    mode != fullMode && mode != menuMode &&
                                    mode != listMode)
					emit menuSelected(menu);
				else
					changeValue(item);
			}
		}
		break;
	case dataColIdx:
		changeValue(item);
		break;
	}

skip:
	//printf("contentsMouseReleaseEvent: %d,%d\n", p.x(), p.y());
	Parent::mouseReleaseEvent(e);
}

void ConfigList::mouseDoubleClickEvent(QMouseEvent* e)
{
	QPoint p = e->pos();
	ConfigItem* item = (ConfigItem*)itemAt(p);
	struct menu *menu;
	enum prop_type ptype;

	if (!item)
		goto skip;
	if (item->goParent) {
		emit parentSelected();
		goto skip;
	}
	menu = item->menu;
	if (!menu)
		goto skip;
	ptype = menu->prompt ? menu->prompt->type : P_UNKNOWN;
	if (ptype == P_MENU && mode != listMode) {
		if (mode == singleMode)
			emit itemSelected(menu);
		else if (mode == symbolMode)
			emit menuSelected(menu);
	} else if (menu->sym)
		changeValue(item);

skip:
	//printf("contentsMouseDoubleClickEvent: %d,%d\n", p.x(), p.y());
	Parent::mouseDoubleClickEvent(e);
}

void ConfigList::focusInEvent(QFocusEvent *e)
{
	struct menu *menu = NULL;

	Parent::focusInEvent(e);

	ConfigItem* item = (ConfigItem *)currentItem();
	if (item) {
		setSelected(item, true);
		menu = item->menu;
	}
	emit gotFocus(menu);
}

void ConfigList::contextMenuEvent(QContextMenuEvent *e)
{
	if (!headerPopup) {
		QAction *action;

		headerPopup = new QMenu(this);
		action = new QAction("Show Name", this);
		action->setCheckable(true);
		connect(action, &QAction::toggled,
			this, &ConfigList::setShowName);
		connect(this, &ConfigList::showNameChanged,
			action, &QAction::setChecked);
		action->setChecked(showName);
		headerPopup->addAction(action);
		headerPopup->addAction(addSymbolFromContextMenu);
	}

	headerPopup->exec(e->globalPos());
	e->accept();
}

void ConfigList::setShowName(bool on)
{
	if (showName == on)
		return;

	showName = on;
	reinit();
	emit showNameChanged(on);
}

QList<ConfigList *> ConfigList::allLists;
QAction *ConfigList::showNormalAction;
QAction *ConfigList::showAllAction;
QAction *ConfigList::showPromptAction;
QAction *ConfigList::addSymbolFromContextMenu;

void ConfigList::setAllOpen(bool open)
{
	QTreeWidgetItemIterator it(this);

	while (*it) {
		(*it)->setExpanded(open);

		++it;
	}
}

ConfigInfoView::ConfigInfoView(QWidget* parent, const char *name)
	: Parent(parent), sym(0), _menu(0)
{
	setObjectName(name);
	setOpenLinks(false);

	if (!objectName().isEmpty()) {
		configSettings->beginGroup(objectName());
		setShowDebug(configSettings->value("/showDebug", false).toBool());
		configSettings->endGroup();
		connect(configApp, &QApplication::aboutToQuit,
			this, &ConfigInfoView::saveSettings);
	}

	contextMenu = createStandardContextMenu();
	QAction *action = new QAction("Show Debug Info", contextMenu);

	action->setCheckable(true);
	connect(action, &QAction::toggled,
		this, &ConfigInfoView::setShowDebug);
	connect(this, &ConfigInfoView::showDebugChanged,
		action, &QAction::setChecked);
	action->setChecked(showDebug());
	contextMenu->addSeparator();
	contextMenu->addAction(action);
}

void ConfigInfoView::saveSettings(void)
{
	if (!objectName().isEmpty()) {
		configSettings->beginGroup(objectName());
		configSettings->setValue("/showDebug", showDebug());
		configSettings->endGroup();
	}
}

void ConfigInfoView::setShowDebug(bool b)
{
	if (_showDebug != b) {
		_showDebug = b;
		if (_menu)
			menuInfo();
		else if (sym)
			symbolInfo();
		emit showDebugChanged(b);
	}
}

void ConfigInfoView::setInfo(struct menu *m)
{
	if (_menu == m)
		return;
	_menu = m;
	sym = NULL;
	if (!_menu)
		clear();
	else
		menuInfo();
}

void ConfigInfoView::symbolInfo(void)
{
	QString str;

	str += "<big>Symbol: <b>";
	str += print_filter(sym->name);
	str += "</b></big><br><br>value: ";
	str += print_filter(sym_get_string_value(sym));
	str += "<br>visibility: ";
	str += sym->visible == yes ? "y" : sym->visible == mod ? "m" : "n";
	str += "<br>";
	str += debug_info(sym);

	setText(str);
}

void ConfigInfoView::menuInfo(void)
{
	struct symbol* sym;
	QString info;
	QTextStream stream(&info);

	sym = _menu->sym;
	if (sym) {
		if (_menu->prompt) {
			stream << "<big><b>";
			stream << print_filter(_menu->prompt->text);
			stream << "</b></big>";
			if (sym->name) {
				stream << " (";
				if (showDebug())
					stream << "<a href=\"" << sym->name << "\">";
				stream << print_filter(sym->name);
				if (showDebug())
					stream << "</a>";
				stream << ")";
			}
		} else if (sym->name) {
			stream << "<big><b>";
			if (showDebug())
				stream << "<a href=\"" << sym->name << "\">";
			stream << print_filter(sym->name);
			if (showDebug())
				stream << "</a>";
			stream << "</b></big>";
		}
		stream << "<br><br>";

		if (showDebug())
			stream << debug_info(sym);

		struct gstr help_gstr = str_new();

		menu_get_ext_help(_menu, &help_gstr);
		stream << print_filter(str_get(&help_gstr));
		str_free(&help_gstr);
	} else if (_menu->prompt) {
		stream << "<big><b>";
		stream << print_filter(_menu->prompt->text);
		stream << "</b></big><br><br>";
		if (showDebug()) {
			if (_menu->prompt->visible.expr) {
				stream << "&nbsp;&nbsp;dep: ";
				expr_print(_menu->prompt->visible.expr,
					   expr_print_help, &stream, E_NONE);
				stream << "<br><br>";
			}

			stream << "defined at " << _menu->filename << ":"
			       << _menu->lineno << "<br><br>";
		}
	}

	setText(info);
}

QString ConfigInfoView::debug_info(struct symbol *sym)
{
	QString debug;
	QTextStream stream(&debug);

	stream << "type: ";
	stream << print_filter(sym_type_name(sym->type));
	if (sym_is_choice(sym))
		stream << " (choice)";
	debug += "<br>";
	if (sym->rev_dep.expr) {
		stream << "reverse dep: ";
		expr_print(sym->rev_dep.expr, expr_print_help, &stream, E_NONE);
		stream << "<br>";
	}
	for (struct property *prop = sym->prop; prop; prop = prop->next) {
		switch (prop->type) {
		case P_PROMPT:
		case P_MENU:
			stream << "prompt: ";
			stream << print_filter(prop->text);
			stream << "<br>";
			break;
		case P_DEFAULT:
		case P_SELECT:
		case P_RANGE:
		case P_COMMENT:
		case P_IMPLY:
			stream << prop_get_type_name(prop->type);
			stream << ": ";
			expr_print(prop->expr, expr_print_help,
				   &stream, E_NONE);
			stream << "<br>";
			break;
		default:
			stream << "unknown property: ";
			stream << prop_get_type_name(prop->type);
			stream << "<br>";
		}
		if (prop->visible.expr) {
			stream << "&nbsp;&nbsp;&nbsp;&nbsp;dep: ";
			expr_print(prop->visible.expr, expr_print_help,
				   &stream, E_NONE);
			stream << "<br>";
		}
	}
	stream << "<br>";

	return debug;
}

QString ConfigInfoView::print_filter(const QString &str)
{
	QRegularExpression re("[<>&\"\\n]");
	QString res = str;

	QHash<QChar, QString> patterns;
	patterns['<'] = "&lt;";
	patterns['>'] = "&gt;";
	patterns['&'] = "&amp;";
	patterns['"'] = "&quot;";
	patterns['\n'] = "<br>";

	for (int i = 0; (i = res.indexOf(re, i)) >= 0;) {
		const QString n = patterns.value(res[i], QString());
		if (!n.isEmpty()) {
			res.replace(i, 1, n);
			i += n.length();
		}
	}
	return res;
}

void ConfigInfoView::expr_print_help(void *data, struct symbol *sym, const char *str)
{
	QTextStream *stream = reinterpret_cast<QTextStream *>(data);

	if (sym && sym->name && !(sym->flags & SYMBOL_CONST)) {
		*stream << "<a href=\"" << sym->name << "\">";
		*stream << print_filter(str);
		*stream << "</a>";
	} else {
		*stream << print_filter(str);
	}
}

void ConfigInfoView::clicked(const QUrl &url)
{
	struct menu *m;

	sym = sym_find(url.toEncoded().constData());

	m = sym_get_prompt_menu(sym);
	if (!m) {
		/* Symbol is not visible as a menu */
		symbolInfo();
		emit showDebugChanged(true);
	} else {
		emit menuSelected(m);
	}
}

void ConfigInfoView::contextMenuEvent(QContextMenuEvent *event)
{
	contextMenu->popup(event->globalPos());
	event->accept();
}

ConfigSearchWindow::ConfigSearchWindow(ConfigMainWindow *parent)
	: Parent(parent), result(NULL)
{
	setObjectName("search");
	setWindowTitle("Search Config");

	QVBoxLayout* layout1 = new QVBoxLayout(this);
	layout1->setContentsMargins(11, 11, 11, 11);
	layout1->setSpacing(6);

	QHBoxLayout* layout2 = new QHBoxLayout();
	layout2->setContentsMargins(0, 0, 0, 0);
	layout2->setSpacing(6);
	layout2->addWidget(new QLabel("Find:", this));
	editField = new QLineEdit(this);
	connect(editField, &QLineEdit::returnPressed,
		this, &ConfigSearchWindow::search);
	layout2->addWidget(editField);
	searchButton = new QPushButton("Search", this);
	searchButton->setAutoDefault(false);
	connect(searchButton, &QPushButton::clicked,
		this, &ConfigSearchWindow::search);
	layout2->addWidget(searchButton);
	layout1->addLayout(layout2);

	split = new QSplitter(Qt::Vertical, this);
	list = new ConfigList(split, "search");
	list->mode = listMode;
	info = new ConfigInfoView(split, "search");
	connect(list, &ConfigList::menuChanged,
		info, &ConfigInfoView::setInfo);
	connect(list, &ConfigList::menuChanged,
		parent, &ConfigMainWindow::setMenuLink);
	connect(list, &ConfigList::menuChanged,
		parent, &ConfigMainWindow::conflictSelected);

	connect(list, &ConfigList::updateConflictsViewColorization, this,
		&ConfigSearchWindow::updateConflictsViewColorizationFowarder);
	layout1->addWidget(split);

	QVariant x, y;
	int width, height;
	bool ok;

	configSettings->beginGroup("search");
	width = configSettings->value("/window width", parent->width() / 2).toInt();
	height = configSettings->value("/window height", parent->height() / 2).toInt();
	resize(width, height);
	x = configSettings->value("/window x");
	y = configSettings->value("/window y");
	if (x.isValid() && y.isValid())
		move(x.toInt(), y.toInt());
	QList<int> sizes = configSettings->readSizes("/split", &ok);
	if (ok)
		split->setSizes(sizes);
	configSettings->endGroup();
	connect(configApp, &QApplication::aboutToQuit,
		this, &ConfigSearchWindow::saveSettings);
}

void ConfigSearchWindow::updateConflictsViewColorizationFowarder(void)
{
	emit updateConflictsViewColorization();
}

void ConfigSearchWindow::saveSettings(void)
{
	if (!objectName().isEmpty()) {
		configSettings->beginGroup(objectName());
		configSettings->setValue("/window x", pos().x());
		configSettings->setValue("/window y", pos().y());
		configSettings->setValue("/window width", size().width());
		configSettings->setValue("/window height", size().height());
		configSettings->writeSizes("/split", split->sizes());
		configSettings->endGroup();
	}
}

void ConfigSearchWindow::search(void)
{
	struct symbol **p;
	struct property *prop;
	ConfigItem *lastItem = NULL;

	free(result);
	list->clear();
	info->clear();

	result = sym_re_search(editField->text().toLatin1());
	if (!result)
		return;
	for (p = result; *p; p++) {
		for_all_prompts((*p), prop)
			lastItem = new ConfigItem(list, lastItem, prop->menu);
	}
}

/*
 * Construct the complete config widget
 */
ConfigMainWindow::ConfigMainWindow(void)
	: searchWindow(0)
{
	bool ok = true;
	QVariant x, y;
	int width, height;
	char title[256];

	snprintf(title, sizeof(title), "%s%s",
		rootmenu.prompt->text,
		""
		);
	setWindowTitle(title);

	QRect g = configApp->primaryScreen()->geometry();
	width = configSettings->value("/window width", g.width() - 64).toInt();
	height = configSettings->value("/window height", g.height() - 64).toInt();
	resize(width, height);
	x = configSettings->value("/window x");
	y = configSettings->value("/window y");
	if ((x.isValid())&&(y.isValid()))
		move(x.toInt(), y.toInt());

	// set up icons
	ConfigItem::symbolYesIcon = QIcon(QPixmap(xpm_symbol_yes));
	ConfigItem::symbolModIcon = QIcon(QPixmap(xpm_symbol_mod));
	ConfigItem::symbolNoIcon = QIcon(QPixmap(xpm_symbol_no));
	ConfigItem::choiceYesIcon = QIcon(QPixmap(xpm_choice_yes));
	ConfigItem::choiceNoIcon = QIcon(QPixmap(xpm_choice_no));
	ConfigItem::menuIcon = QIcon(QPixmap(xpm_menu));
	ConfigItem::menubackIcon = QIcon(QPixmap(xpm_menuback));

	QWidget *widget = new QWidget(this);
	setCentralWidget(widget);

	QVBoxLayout *layout = new QVBoxLayout(widget);

	split2 = new QSplitter(Qt::Vertical, widget);
	layout->addWidget(split2);
	split2->setChildrenCollapsible(false);

	split1 = new QSplitter(Qt::Horizontal, split2);
	split1->setChildrenCollapsible(false);

	configList = new ConfigList(split1, "config");

	menuList = new ConfigList(split1, "menu");

	helpText = new ConfigInfoView(split2, "help");
	setTabOrder(configList, helpText);

	split3 = new QSplitter(split2);
	split3->setOrientation(Qt::Vertical);
	conflictsView = new ConflictsView(split3, "help");
	/*
	 * conflictsSelected signal in conflictsview triggers when a conflict is
	 * selected in the view. this line connects that event to conflictselected
	 * event in mainwindow which updates the selection to match (in the
	 * configlist) the symbol that was selected.
	 */
	connect(conflictsView, &ConflictsView::conflictSelected, this,
		&ConfigMainWindow::conflictSelected);
	connect(conflictsView, &ConflictsView::refreshMenu, this,
		&ConfigMainWindow::refreshMenu);
	connect(menuList, &ConfigList::updateConflictsViewColorization,
		conflictsView, &ConflictsView::updateConflictsViewColorization);
	connect(configList, &ConfigList::updateConflictsViewColorization,
		conflictsView, &ConflictsView::updateConflictsViewColorization);

	configList->setFocus();

	backAction = new QAction(QPixmap(xpm_back), "Back", this);
	backAction->setShortcut(QKeySequence::Back);
	connect(backAction, &QAction::triggered,
		this, &ConfigMainWindow::goBack);

	QAction *quitAction = new QAction("&Quit", this);
	quitAction->setShortcut(QKeySequence::Quit);
	connect(quitAction, &QAction::triggered,
		this, &ConfigMainWindow::close);

	QAction *loadAction = new QAction(QPixmap(xpm_load), "&Open", this);
	loadAction->setShortcut(QKeySequence::Open);
	connect(loadAction, &QAction::triggered,
		this, &ConfigMainWindow::loadConfig);

	saveAction = new QAction(QPixmap(xpm_save), "&Save", this);
	saveAction->setShortcut(QKeySequence::Save);
	connect(saveAction, &QAction::triggered,
		this, &ConfigMainWindow::saveConfig);

	conf_set_changed_callback(conf_changed);

	configname = conf_get_configname();

	QAction *saveAsAction = new QAction("Save &As...", this);
	saveAsAction->setShortcut(QKeySequence::SaveAs);
	connect(saveAsAction, &QAction::triggered,
		this, &ConfigMainWindow::saveConfigAs);
	QAction *searchAction = new QAction("&Find", this);
	searchAction->setShortcut(QKeySequence::Find);
	connect(searchAction, &QAction::triggered,
		this, &ConfigMainWindow::searchConfig);
	singleViewAction = new QAction(QPixmap(xpm_single_view), "Single View", this);
	singleViewAction->setCheckable(true);
	connect(singleViewAction, &QAction::triggered,
		this, &ConfigMainWindow::showSingleView);
	splitViewAction = new QAction(QPixmap(xpm_split_view), "Split View", this);
	splitViewAction->setCheckable(true);
	connect(splitViewAction, &QAction::triggered,
		this, &ConfigMainWindow::showSplitView);
	fullViewAction = new QAction(QPixmap(xpm_tree_view), "Full View", this);
	fullViewAction->setCheckable(true);
	connect(fullViewAction, &QAction::triggered,
		this, &ConfigMainWindow::showFullView);

	QAction *showNameAction = new QAction("Show Name", this);
	  showNameAction->setCheckable(true);
	connect(showNameAction, &QAction::toggled,
		configList, &ConfigList::setShowName);
	showNameAction->setChecked(configList->showName);

	QActionGroup *optGroup = new QActionGroup(this);
	optGroup->setExclusive(true);
	connect(optGroup, &QActionGroup::triggered,
		configList, &ConfigList::setOptionMode);
	connect(optGroup, &QActionGroup::triggered,
		menuList, &ConfigList::setOptionMode);

	ConfigList::showNormalAction = new QAction("Show Normal Options", optGroup);
	ConfigList::showNormalAction->setCheckable(true);
	ConfigList::showAllAction = new QAction("Show All Options", optGroup);
	ConfigList::showAllAction->setCheckable(true);
	ConfigList::showPromptAction = new QAction("Show Prompt Options", optGroup);
	ConfigList::showPromptAction->setCheckable(true);
	ConfigList::addSymbolFromContextMenu =
		new QAction("Add symbol from context menu");
	connect(ConfigList::addSymbolFromContextMenu, &QAction::triggered,
		conflictsView, &ConflictsView::addSymbol);

	QAction *showDebugAction = new QAction("Show Debug Info", this);
	  showDebugAction->setCheckable(true);
	connect(showDebugAction, &QAction::toggled,
		helpText, &ConfigInfoView::setShowDebug);
	  showDebugAction->setChecked(helpText->showDebug());

	QAction *showIntroAction = new QAction("Introduction", this);
	connect(showIntroAction, &QAction::triggered,
		this, &ConfigMainWindow::showIntro);
	QAction *showAboutAction = new QAction("About", this);
	connect(showAboutAction, &QAction::triggered,
		this, &ConfigMainWindow::showAbout);

	// init tool bar
	QToolBar *toolBar = addToolBar("Tools");
	toolBar->addAction(backAction);
	toolBar->addSeparator();
	toolBar->addAction(loadAction);
	toolBar->addAction(saveAction);
	toolBar->addSeparator();
	toolBar->addAction(singleViewAction);
	toolBar->addAction(splitViewAction);
	toolBar->addAction(fullViewAction);

	// create file menu
	QMenu *menu = menuBar()->addMenu("&File");
	menu->addAction(loadAction);
	menu->addAction(saveAction);
	menu->addAction(saveAsAction);
	menu->addSeparator();
	menu->addAction(quitAction);

	// create edit menu
	menu = menuBar()->addMenu("&Edit");
	menu->addAction(searchAction);

	// create options menu
	menu = menuBar()->addMenu("&Option");
	menu->addAction(showNameAction);
	menu->addSeparator();
	menu->addActions(optGroup->actions());
	menu->addSeparator();
	menu->addAction(showDebugAction);

	// create help menu
	menu = menuBar()->addMenu("&Help");
	menu->addAction(showIntroAction);
	menu->addAction(showAboutAction);

	connect(helpText, &ConfigInfoView::anchorClicked,
		helpText, &ConfigInfoView::clicked);

	connect(configList, &ConfigList::menuChanged,
		helpText, &ConfigInfoView::setInfo);
	connect(configList, &ConfigList::menuChanged,
		conflictsView, &ConflictsView::menuChanged);
	connect(configList, &ConfigList::menuSelected,
		this, &ConfigMainWindow::changeMenu);
	connect(configList, &ConfigList::itemSelected,
		this, &ConfigMainWindow::changeItens);
	connect(configList, &ConfigList::parentSelected,
		this, &ConfigMainWindow::goBack);
	connect(menuList, &ConfigList::menuChanged,
		helpText, &ConfigInfoView::setInfo);
	connect(menuList, &ConfigList::menuChanged,
		conflictsView, &ConflictsView::menuChanged);
	connect(menuList, &ConfigList::menuSelected,
		this, &ConfigMainWindow::changeMenu);

	connect(configList, &ConfigList::gotFocus,
		helpText, &ConfigInfoView::setInfo);
	connect(menuList, &ConfigList::gotFocus,
		helpText, &ConfigInfoView::setInfo);
	connect(menuList, &ConfigList::gotFocus,
		this, &ConfigMainWindow::listFocusChanged);
	connect(helpText, &ConfigInfoView::menuSelected,
		this, &ConfigMainWindow::setMenuLink);

	connect(configApp, &QApplication::aboutToQuit,
		this, &ConfigMainWindow::saveSettings);

	conf_read(NULL);

	QString listMode = configSettings->value("/listMode", "symbol").toString();
	if (listMode == "single")
		showSingleView();
	else if (listMode == "full")
		showFullView();
	else /*if (listMode == "split")*/
		showSplitView();

	// UI setup done, restore splitter positions
	QList<int> sizes = configSettings->readSizes("/split1", &ok);
	if (ok)
		split1->setSizes(sizes);

	sizes = configSettings->readSizes("/split2", &ok);
	if (ok)
		split2->setSizes(sizes);
}

void ConfigMainWindow::loadConfig(void)
{
	QString str;

	str = QFileDialog::getOpenFileName(this, "", configname);
	if (str.isNull())
		return;

	if (conf_read(str.toLocal8Bit().constData()))
		QMessageBox::information(this, "qconf", "Unable to load configuration!");

	configname = str;

	ConfigList::updateListAllForAll();
}

bool ConfigMainWindow::saveConfig(void)
{
	if (conf_write(configname.toLocal8Bit().constData())) {
		QMessageBox::information(this, "qconf", "Unable to save configuration!");
		return false;
	}
	conf_write_autoconf(0);

	return true;
}

void ConfigMainWindow::saveConfigAs(void)
{
	QString str;

	str = QFileDialog::getSaveFileName(this, "", configname);
	if (str.isNull())
		return;

	if (conf_write(str.toLocal8Bit().constData())) {
		QMessageBox::information(this, "qconf", "Unable to save configuration!");
	}
	conf_write_autoconf(0);

	configname = str;
}

void ConfigMainWindow::searchConfig(void)
{
	if (!searchWindow)
		searchWindow = new ConfigSearchWindow(this);
	searchWindow->show();
}

void ConfigMainWindow::changeItens(struct menu *menu)
{
	configList->setRootMenu(menu);
}

void ConfigMainWindow::changeMenu(struct menu *menu)
{
	menuList->setRootMenu(menu);
}

void ConfigMainWindow::setMenuLink(struct menu *menu)
{
	struct menu *parent;
	ConfigList* list = NULL;
	ConfigItem* item;

	if (configList->menuSkip(menu))
		return;

	switch (configList->mode) {
	case singleMode:
		list = configList;
		parent = menu_get_parent_menu(menu);
		if (!parent)
			return;
		list->setRootMenu(parent);
		break;
	case menuMode:
		if (menu->flags & MENU_ROOT) {
			menuList->setRootMenu(menu);
			configList->clearSelection();
			list = configList;
		} else {
			parent = menu_get_parent_menu(menu->parent);
			if (!parent)
				return;

			/* Select the config view */
			item = configList->findConfigItem(parent);
			if (item) {
				configList->setSelected(item, true);
				configList->scrollToItem(item);
			}

			menuList->setRootMenu(parent);
			menuList->clearSelection();
			list = menuList;
		}
		break;
	case fullMode:
		list = configList;
		break;
	default:
		break;
	}

	if (list) {
		item = list->findConfigItem(menu);
		if (item) {
			list->setSelected(item, true);
			list->scrollToItem(item);
			list->setFocus();
			helpText->setInfo(menu);
		}
	}
}

void ConfigMainWindow::listFocusChanged(void)
{
	if (menuList->mode == menuMode)
		configList->clearSelection();
}

void ConfigMainWindow::goBack(void)
{
	configList->setParentMenu();
}

void ConfigMainWindow::showSingleView(void)
{
	singleViewAction->setEnabled(false);
	singleViewAction->setChecked(true);
	splitViewAction->setEnabled(true);
	splitViewAction->setChecked(false);
	fullViewAction->setEnabled(true);
	fullViewAction->setChecked(false);

	backAction->setEnabled(true);

	menuList->hide();
	menuList->setRootMenu(0);
	configList->mode = singleMode;
	if (configList->rootEntry == &rootmenu)
		configList->updateListAll();
	else
		configList->setRootMenu(&rootmenu);
	configList->setFocus();
}

void ConfigMainWindow::showSplitView(void)
{
	singleViewAction->setEnabled(true);
	singleViewAction->setChecked(false);
	splitViewAction->setEnabled(false);
	splitViewAction->setChecked(true);
	fullViewAction->setEnabled(true);
	fullViewAction->setChecked(false);

	backAction->setEnabled(false);

	configList->mode = menuMode;
	if (configList->rootEntry == &rootmenu)
		configList->updateListAll();
	else
		configList->setRootMenu(&rootmenu);
	configList->setAllOpen(true);
	configApp->processEvents();
	menuList->mode = symbolMode;
	menuList->setRootMenu(&rootmenu);
	menuList->setAllOpen(true);
	menuList->show();
	menuList->setFocus();
}

void ConfigMainWindow::conflictSelected(struct menu *men)
{
	configList->clearSelection();
	menuList->clearSelection();
	emit(setMenuLink(men));
}

void ConfigMainWindow::showFullView(void)
{
	singleViewAction->setEnabled(true);
	singleViewAction->setChecked(false);
	splitViewAction->setEnabled(true);
	splitViewAction->setChecked(false);
	fullViewAction->setEnabled(false);
	fullViewAction->setChecked(true);

	backAction->setEnabled(false);

	menuList->hide();
	menuList->setRootMenu(0);
	configList->mode = fullMode;
	if (configList->rootEntry == &rootmenu)
		configList->updateListAll();
	else
		configList->setRootMenu(&rootmenu);
	configList->setFocus();
}

/*
 * ask for saving configuration before quitting
 */
void ConfigMainWindow::closeEvent(QCloseEvent* e)
{
	if (!conf_get_changed()) {
		e->accept();
		return;
	}

	QMessageBox mb(QMessageBox::Icon::Warning, "qconf",
		       "Save configuration?");

	QPushButton *yb = mb.addButton(QMessageBox::Yes);
	QPushButton *db = mb.addButton(QMessageBox::No);
	QPushButton *cb = mb.addButton(QMessageBox::Cancel);

	yb->setText("&Save Changes");
	db->setText("&Discard Changes");
	cb->setText("Cancel Exit");

	mb.setDefaultButton(yb);
	mb.setEscapeButton(cb);

	switch (mb.exec()) {
	case QMessageBox::Yes:
		if (saveConfig())
			e->accept();
		else
			e->ignore();
		break;
	case QMessageBox::No:
		e->accept();
		break;
	case QMessageBox::Cancel:
		e->ignore();
		break;
	}
}

void ConfigMainWindow::showIntro(void)
{
	static const QString str =
		"Welcome to the qconf graphical configuration tool.\n"
		"\n"
		"For bool and tristate options, a blank box indicates the "
		"feature is disabled, a check indicates it is enabled, and a "
		"dot indicates that it is to be compiled as a module. Clicking "
		"on the box will cycle through the three states. For int, hex, "
		"and string options, double-clicking or pressing F2 on the "
		"Value cell will allow you to edit the value.\n"
		"\n"
		"If you do not see an option (e.g., a device driver) that you "
		"believe should be present, try turning on Show All Options "
		"under the Options menu. Enabling Show Debug Info will help you"
		"figure out what other options must be enabled to support the "
		"option you are interested in, and hyperlinks will navigate to "
		"them.\n"
		"\n"
		"Toggling Show Debug Info under the Options menu will show the "
		"dependencies, which you can then match by examining other "
		"options.\n";

	QMessageBox::information(this, "qconf", str);
}

void ConfigMainWindow::showAbout(void)
{
	static const QString str = "qconf is Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>.\n"
		"Copyright (C) 2015 Boris Barbulovski <bbarbulovski@gmail.com>.\n"
		"\n"
		"Bug reports and feature request can also be entered at http://bugzilla.kernel.org/\n"
		"\n"
		"Qt Version: ";

	QMessageBox::information(this, "qconf", str + qVersion());
}

void ConfigMainWindow::saveSettings(void)
{
	configSettings->setValue("/window x", pos().x());
	configSettings->setValue("/window y", pos().y());
	configSettings->setValue("/window width", size().width());
	configSettings->setValue("/window height", size().height());

	QString entry;
	switch(configList->mode) {
	case singleMode :
		entry = "single";
		break;

	case symbolMode :
		entry = "split";
		break;

	case fullMode :
		entry = "full";
		break;

	default:
		break;
	}
	configSettings->setValue("/listMode", entry);

	configSettings->writeSizes("/split1", split1->sizes());
	configSettings->writeSizes("/split2", split2->sizes());
}

void ConfigMainWindow::conf_changed(bool dirty)
{
	if (saveAction)
		saveAction->setEnabled(dirty);
}

void ConfigMainWindow::refreshMenu(void)
{
	configList->updateListAll();
}

void QTableWidget::dropEvent(QDropEvent *event)
{
}

void ConflictsView::addPicoSatNote(QToolBar &toolbar)
{
	QLabel &label = *new QLabel;
	auto &iconLabel = *new QLabel();
	iconLabel.setPixmap(
		style()->standardIcon(
			       QStyle::StandardPixmap::SP_MessageBoxInformation)
			.pixmap(20, 20));
	label.setText(
		"The conflict resolver requires that PicoSAT is available as a library.");
	QAction &showDialog = *new QAction();
	showDialog.setIconText("Install PicoSAT...");
	toolbar.addWidget(&iconLabel);
	toolbar.addWidget(&label);
	toolbar.addAction(&showDialog);
	connect(&showDialog, &QAction::triggered,
		[this]() { (new PicoSATInstallInfoWindow(this))->show(); });
}

ConflictsView::ConflictsView(QWidget *parent, const char *name)
	: Parent(parent)
{
	/*
	 * 	- topLevelLayout
	 * 		- picoSatContainer
	 *  		- picoSatLayout
	 *  			- ...
	 *		- conflictsViewContainer
	 *			- horizontalLayout
	 *				- verticalLayout
	 *				- solutionLayout
	 */
	currentSelectedMenu = nullptr;
	setObjectName(name);
	QVBoxLayout *topLevelLayout = new QVBoxLayout(this);
	QWidget *conflictsViewContainer = new QWidget;
	if (!picosat_available) {
		conflictsViewContainer->setDisabled(true);
		QWidget *picoSatContainer = new QWidget;
		topLevelLayout->addWidget(picoSatContainer);
		QHBoxLayout *picoSatLayout = new QHBoxLayout(picoSatContainer);
		QToolBar *picoToolbar = new QToolBar(picoSatContainer);
		picoSatLayout->addWidget(picoToolbar);
		picoSatLayout->addStretch();
		addPicoSatNote(*picoToolbar);
	}
	topLevelLayout->addWidget(conflictsViewContainer);

	QHBoxLayout *horizontalLayout = new QHBoxLayout(conflictsViewContainer);
	QVBoxLayout *verticalLayout = new QVBoxLayout;
	verticalLayout->setContentsMargins(0, 0, 0, 0);
	conflictsToolBar =
		new QToolBar("ConflictTools", conflictsViewContainer);
	// toolbar buttons [n] [m] [y] [calculate fixes] [remove]
	QAction *addSymbol = new QAction("Add Symbol");
	QAction *setConfigSymbolAsNo = new QAction("N");
	QAction *setConfigSymbolAsModule = new QAction("M");
	QAction *setConfigSymbolAsYes = new QAction("Y");
	fixConflictsAction_ = new QAction("Calculate Fixes");
	QAction *removeSymbol = new QAction("Remove Symbol");
	QMovie *loadingGif = new QMovie("scripts/kconfig/loader.gif");
	auto loadingLabel = new QLabel;

	if (loadingGif->isValid()) {
		loadingGif->setScaledSize(loadingGif->scaledSize().scaled(
			20, 20, Qt::KeepAspectRatioByExpanding));
		loadingGif->start();
		loadingLabel->setMovie(loadingGif);
	} else {
		loadingLabel->setText("Calculating...");
	}

	//if you change the order of buttons here, change the code where
	//module button was disabled if symbol is boolean, selecting module button
	//depends on a specific index in list of action
	fixConflictsAction_->setCheckable(false);
	conflictsToolBar->addAction(addSymbol);
	conflictsToolBar->addAction(setConfigSymbolAsNo);
	conflictsToolBar->addAction(setConfigSymbolAsModule);
	conflictsToolBar->addAction(setConfigSymbolAsYes);
	conflictsToolBar->addAction(fixConflictsAction_);
	conflictsToolBar->addAction(removeSymbol);
	// loadingLabel->setMargin(5);
	loadingLabel->setContentsMargins(5, 5, 5, 5);
	loadingAction = conflictsToolBar->addWidget(loadingLabel);
	loadingAction->setVisible(false);

	verticalLayout->addWidget(conflictsToolBar);

	connect(addSymbol, &QAction::triggered, this,
		&ConflictsView::addSymbol);
	connect(setConfigSymbolAsNo, &QAction::triggered, this,
		&ConflictsView::changeToNo);
	connect(setConfigSymbolAsModule, &QAction::triggered, this,
		&ConflictsView::changeToModule);
	connect(setConfigSymbolAsYes, &QAction::triggered, this,
		&ConflictsView::changeToYes);
	connect(removeSymbol, &QAction::triggered, this,
		&ConflictsView::removeSymbol);
	connect(this, &ConflictsView::resultsReady, this,
		&ConflictsView::updateResults);
	//connect clicking 'calculate fixes' to 'change all symbol values to fix all conflicts'
	// no longer used anymore for now.
	connect(fixConflictsAction_, &QAction::triggered, this,
		&ConflictsView::calculateFixes);

	conflictsTable = (QTableWidget *)new dropAbleView(this);
	conflictsTable->setRowCount(0);
	conflictsTable->setColumnCount(3);
	conflictsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	conflictsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

	conflictsTable->setHorizontalHeaderLabels(
		QStringList() << "Name" << "Wanted value" << "Current value");
	verticalLayout->addWidget(conflictsTable);

	conflictsTable->setDragDropMode(QAbstractItemView::DropOnly);
	setAcceptDrops(true);

	connect(conflictsTable, &QTableWidget::cellClicked, this,
		&ConflictsView::cellClicked);
	horizontalLayout->addLayout(verticalLayout);

	// populate the solution view on the right hand side:
	QVBoxLayout *solutionLayout = new QVBoxLayout();
	solutionLayout->setContentsMargins(0, 0, 0, 0);
	solutionSelector = new QComboBox();
	connect(solutionSelector,
		QOverload<int>::of(&QComboBox::currentIndexChanged),
		[=](int index) { changeSolutionTable(index); });
	solutionTable = new QTableWidget();
	solutionTable->setRowCount(0);
	solutionTable->setColumnCount(2);
	solutionTable->setHorizontalHeaderLabels(QStringList()
						 << "Name" << "New Value");
	solutionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

	applyFixButton = new QPushButton("Apply Selected solution");
	connect(applyFixButton, &QPushButton::clicked, this,
		&ConflictsView::applyFixButtonClick);

	numSolutionLabel = new QLabel("Solutions:");
	solutionLayout->addWidget(numSolutionLabel);
	solutionLayout->addWidget(solutionSelector);
	solutionLayout->addWidget(solutionTable);
	solutionLayout->addWidget(applyFixButton);

	horizontalLayout->addLayout(solutionLayout);
}

void ConflictsView::applyFixButtonClick()
{
	signed int solution_number = solutionSelector->currentIndex();

	if (solution_number == -1 || solution_output == NULL) {
		return;
	}

	apply_fix(solution_output[solution_number]);

	ConfigList::updateListForAll();
	for (int i = 0; i < conflictsTable->rowCount(); i++) {
		conflictsTable->item(i, 2)->setText(
			conflictsTable->item(i, 1)->text());
	}
	updateConflictsViewColorization();
	QMessageBox msgBox;
	msgBox.setText("The solution has been applied.");
	msgBox.exec();
}

void ConflictsView::changeToYes()
{
	QItemSelectionModel *select = conflictsTable->selectionModel();
	if (select->hasSelection()) {
		QModelIndexList rows = select->selectedRows();
		for (int i = 0; i < rows.count(); i++) {
			conflictsTable->item(rows[i].row(), 1)
				->setText(tristate_value_to_string(yes));
		}
	}
}

void ConflictsView::changeToModule()
{
	QItemSelectionModel *select = conflictsTable->selectionModel();
	if (select->hasSelection()) {
		QModelIndexList rows = select->selectedRows();
		for (int i = 0; i < rows.count(); i++) {
			conflictsTable->item(rows[i].row(), 1)
				->setText(tristate_value_to_string(mod));
		}
	}
}

void ConflictsView::changeToNo()
{
	QItemSelectionModel *select = conflictsTable->selectionModel();
	if (select->hasSelection()) {
		QModelIndexList rows = select->selectedRows();
		for (int i = 0; i < rows.count(); i++) {
			conflictsTable->item(rows[i].row(), 1)
				->setText(tristate_value_to_string(no));
		}
	}
}

void ConflictsView::menuChanged(struct menu *m)
{
	currentSelectedMenu = m;
}

void ConflictsView::addSymbol()
{
	addSymbolFromMenu(currentSelectedMenu);
}

void ConflictsView::selectionChanged(QList<QTreeWidgetItem *> selection)
{
	currentSelection = selection;
}

void ConflictsView::addSymbolFromMenu(struct menu *m)
{
	// adds a symbol to the conflict resolver list
	if (m != nullptr) {
		if (m->sym != nullptr) {
			struct symbol *sym = m->sym;
			tristate currentval = sym_get_tristate_value(sym);
			//if symbol is not added yet:
			QAbstractItemModel *tableModel =
				conflictsTable->model();
			QModelIndexList matches = tableModel->match(
				tableModel->index(0, 0), Qt::DisplayRole,
				QString(sym->name));
			if (matches.isEmpty()) {
				conflictsTable->insertRow(
					conflictsTable->rowCount());
				conflictsTable->setItem(
					conflictsTable->rowCount() - 1, 0,
					new QTableWidgetItem(sym->name));
				conflictsTable->setItem(
					conflictsTable->rowCount() - 1, 1,
					new QTableWidgetItem(
						tristate_value_to_string(
							currentval)));
				conflictsTable->setItem(
					conflictsTable->rowCount() - 1, 2,
					new QTableWidgetItem(
						tristate_value_to_string(
							currentval)));
			} else {
				conflictsTable->item(matches[0].row(), 2)
					->setText(tristate_value_to_string(
						currentval));
			}
		}
	}
}

void ConflictsView::addSymbolFromContextMenu()
{
	struct menu *menu;

	if (currentSelection.count() < 0) {
		return;
	}
	for (auto el : currentSelection) {
		ConfigItem *item = (ConfigItem *)el;
		if (!item) {
			continue;
		}
		menu = item->menu;
		addSymbolFromMenu(menu);
	}
}

void ConflictsView::removeSymbol()
{
	QItemSelectionModel *select = conflictsTable->selectionModel();
	QAbstractItemModel *itemModel = select->model();
	if (select->hasSelection()) {
		QModelIndexList rows = select->selectedRows();
		itemModel->removeRows(rows[0].row(), rows.size());
	}
}

void ConflictsView::cellClicked(int row, int column)
{
	auto itemText = conflictsTable->item(row, 0)->text().toUtf8().data();
	struct property *prop;
	struct menu *men;
	struct symbol *sym = sym_find(itemText);

	if (sym == NULL)
		return;
	prop = sym->prop;
	men = prop->menu;
	// uncommenting following like somehow disables click signal of 'apply selected solution'
	if (sym->type == symbol_type::S_BOOLEAN) {
		//disable module button
		conflictsToolBar->actions()[2]->setDisabled(true);
	} else {
		//enable module button
		conflictsToolBar->actions()[2]->setDisabled(false);
	}
	if (column == 1) {
		// cycle to new value
		tristate old_val = string_value_to_tristate(
			conflictsTable->item(row, 1)->text());
		tristate new_val = old_val;
		switch (old_val) {
		case no:
			new_val = mod;
			break;
		case mod:
			new_val = yes;
			break;
		case yes:
			new_val = no;
			break;
		}
		if (sym->type == S_BOOLEAN && new_val == mod)
			new_val = yes;
		conflictsTable->item(row, 1)->setText(
			tristate_value_to_string(new_val));
	}
	emit(conflictSelected(men));
}

void ConflictsView::changeSolutionTable(int solution_number)
{
	size_t i;

	if (solution_output == nullptr || solution_number < 0) {
		return;
	}
	struct sfix_list *selected_solution = solution_output[solution_number];
	current_solution_number = solution_number;
	solutionTable->setRowCount(0);
	i = 0;
	for (struct list_head *curr = selected_solution->list.next;
	     curr != &selected_solution->list; curr = curr->next, ++i) {
		solutionTable->insertRow(solutionTable->rowCount());
		struct symbol_fix *cur_symbol =
			select_symbol(selected_solution, i);

		QTableWidgetItem *symbol_name =
			new QTableWidgetItem(cur_symbol->sym->name);

		solutionTable->setItem(solutionTable->rowCount() - 1, 0,
				       symbol_name);

		if (cur_symbol->type == symbolfix_type::SF_BOOLEAN) {
			QTableWidgetItem *symbol_value = new QTableWidgetItem(
				tristate_value_to_string(cur_symbol->tri));
			solutionTable->setItem(solutionTable->rowCount() - 1, 1,
					       symbol_value);
		} else if (cur_symbol->type == symbolfix_type::SF_NONBOOLEAN) {
			QTableWidgetItem *symbol_value =
				new QTableWidgetItem(cur_symbol->nb_val.s);
			solutionTable->setItem(solutionTable->rowCount() - 1, 1,
					       symbol_value);
		} else {
			QTableWidgetItem *symbol_value =
				new QTableWidgetItem(cur_symbol->disallowed.s);
			solutionTable->setItem(solutionTable->rowCount() - 1, 1,
					       symbol_value);
		}
	}
	updateConflictsViewColorization();
}

void ConflictsView::updateConflictsViewColorization(void)
{
	auto green = QColor(0, 170, 0);
	auto red = QColor(255, 0, 0);
	auto grey = QColor(180, 180, 180);

	if (solutionTable->rowCount() == 0 || current_solution_number < 0)
		return;

	for (int i = 0; i < solutionTable->rowCount(); i++) {
		QTableWidgetItem *symbol = solutionTable->item(i, 0);
		//symbol from solution list
		struct symbol_fix *cur_symbol = select_symbol(
			solution_output[current_solution_number], i);

		// if symbol is editable but the value is not the target value from solution we got, the color is red
		// if symbol is editable but the value is the target value from solution we got, the color is green
		// if symbol is not editable , the value is not the target value, the color is grey
		// if symbol is not editable , the value is the target value, the color is green
		auto editable = sym_string_within_range(
			cur_symbol->sym,
			tristate_value_to_string(cur_symbol->tri)
				.toStdString()
				.c_str());
		auto _symbol =
			solutionTable->item(i, 0)->text().toUtf8().data();
		struct symbol *sym_ = sym_find(_symbol);

		tristate current_value_of_symbol = sym_get_tristate_value(sym_);
		tristate target_value_of_symbol = string_value_to_tristate(
			solutionTable->item(i, 1)->text());
		bool symbol_value_same_as_target = current_value_of_symbol ==
						   target_value_of_symbol;

		if (editable && !symbol_value_same_as_target) {
			symbol->setForeground(red);
		} else if (editable && symbol_value_same_as_target) {
			symbol->setForeground(green);
		} else if (!editable && !symbol_value_same_as_target) {
			symbol->setForeground(grey);
		} else if (!editable && symbol_value_same_as_target) {
			symbol->setForeground(green);
		}
	}
}

void ConflictsView::runSatConfAsync()
{
	//loop through the rows in conflicts table adding each row into the array:
	struct symbol_dvalue *p = nullptr;
	std::vector<struct symbol_dvalue *> wanted_symbols;

	p = static_cast<struct symbol_dvalue *>(calloc(
		conflictsTable->rowCount(), sizeof(struct symbol_dvalue)));
	if (!p) {
		printf("memory allocation error\n");
		return;
	}

	for (int i = 0; i < conflictsTable->rowCount(); i++) {
		struct symbol_dvalue *tmp = (p + i);
		auto _symbol =
			conflictsTable->item(i, 0)->text().toUtf8().data();
		struct symbol *sym = sym_find(_symbol);

		tmp->sym = sym;
		tmp->type = static_cast<symboldv_type>(
			sym->type == symbol_type::S_BOOLEAN ? 0 : 1);
		tmp->tri = string_value_to_tristate(
			conflictsTable->item(i, 1)->text());
		wanted_symbols.push_back(tmp);
	}
	fixConflictsAction_->setText("Cancel");
	loadingAction->setVisible(true);

	solution_output = run_satconf(wanted_symbols.data(),
				      wanted_symbols.size(), &num_solutions);

	free(p);
	emit resultsReady();
	{
		std::lock_guard<std::mutex> lk{ satconf_mutex };
		satconf_cancelled = true;
	}
	satconf_cancellation_cv.notify_one();
}

void ConflictsView::updateResults(void)
{
	fixConflictsAction_->setText("Calculate Fixes");
	loadingAction->setVisible(false);
	if (!(solution_output == nullptr || num_solutions == 0)) {
		solutionSelector->clear();
		for (unsigned int i = 0; i < num_solutions; i++)
			solutionSelector->addItem(QString::number(i + 1));
		// populate the solution table from the first solution gotten
		numSolutionLabel->setText(
			QString("Solutions: (%1) found").arg(num_solutions));
		changeSolutionTable(0);
	} else {
		QMessageBox msgBox;
		msgBox.setText("All symbols are already within range.");
		msgBox.exec();
	}
	if (runSatConfAsyncThread->joinable()) {
		runSatConfAsyncThread->join();
		delete runSatConfAsyncThread;
		runSatConfAsyncThread = nullptr;
	}
}

void ConflictsView::calculateFixes()
{
	if (conflictsTable->rowCount() == 0) {
		printd("table is empty\n");
		return;
	}

	if (runSatConfAsyncThread == nullptr) {
		// fire away asynchronous call
		std::unique_lock<std::mutex> lk{ satconf_mutex };

		numSolutionLabel->setText(QString("Solutions: "));
		solutionSelector->clear();
		solutionTable->setRowCount(0);
		satconf_cancelled = false;
		runSatConfAsyncThread =
			new std::thread(&ConflictsView::runSatConfAsync, this);
	} else {
		printd("Interrupting rangefix\n");
		interrupt_rangefix();
		std::unique_lock<std::mutex> lk{ satconf_mutex };
		satconf_cancellation_cv.wait(lk, [this] {
			return satconf_cancelled == true;
		});
	}
}

void ConflictsView::changeAll(void)
{
	// not implemented for now
	return;
}

ConflictsView::~ConflictsView(void)
{
}

void fixup_rootmenu(struct menu *menu)
{
	struct menu *child;
	static int menu_cnt = 0;

	menu->flags |= MENU_ROOT;
	for (child = menu->list; child; child = child->next) {
		if (child->prompt && child->prompt->type == P_MENU) {
			menu_cnt++;
			fixup_rootmenu(child);
			menu_cnt--;
		} else if (!menu_cnt)
			fixup_rootmenu(child);
	}
}

static const char *progname;

static void usage(void)
{
	printf("%s [-s] <config>\n", progname);
	exit(0);
}

int main(int ac, char** av)
{
	ConfigMainWindow* v;
	const char *name;

	progname = av[0];
	if (ac > 1 && av[1][0] == '-') {
		switch (av[1][1]) {
		case 's':
			conf_set_message_callback(NULL);
			break;
		case 'h':
		case '?':
			usage();
		}
		name = av[2];
	} else
		name = av[1];
	if (!name)
		usage();

	conf_parse(name);
	fixup_rootmenu(&rootmenu);
	//zconfdump(stdout);

	picosat_available = load_picosat();

	configApp = new QApplication(ac, av);

	configSettings = new ConfigSettings();
	configSettings->beginGroup("/kconfig/qconf");
	v = new ConfigMainWindow();

	//zconfdump(stdout);

	v->show();
	configApp->exec();

	configSettings->endGroup();
	delete configSettings;
	delete v;
	delete configApp;

	return 0;
}

dropAbleView::dropAbleView(QWidget *parent)
	: QTableWidget(parent)
{
}

dropAbleView::~dropAbleView()
{
}
void dropAbleView::dropEvent(QDropEvent *event)
{
	event->acceptProposedAction();
}

static QString tristate_value_to_string(tristate val)
{
	switch (val) {
	case yes:
		return QString::fromStdString("Y");
	case mod:
		return QString::fromStdString("M");
	case no:
		return QString::fromStdString("N");
	default:
		return QString::fromStdString("");
	}
}

static tristate string_value_to_tristate(QString s)
{
	if (s == "Y")
		return tristate::yes;
	else if (s == "M")
		return tristate::mod;
	else if (s == "N")
		return tristate::no;
	else
		return tristate::no;
}

PicoSATInstallInfoWindow::PicoSATInstallInfoWindow(QWidget *parent)
	: QDialog(parent)
{
	QVBoxLayout &layout = *new QVBoxLayout(this);
	QLabel &text = *new QLabel();
	text.setWordWrap(true);
	layout.addWidget(&text);
	text.setTextFormat(Qt::MarkdownText);
	text.setTextInteractionFlags(Qt::TextSelectableByMouse);
	text.setTextInteractionFlags(Qt::TextBrowserInteraction);
	text.setOpenExternalLinks(true);
	text.setText(R""""(
Install the picosat package or build the library yourself:

## Debian-based distributions

```sh
sudo apt install picosat
```

## Fedora

```sh
sudo dnf install picosat
```

## Other

You can also build PicoSAT yourself from the
[sources](https://fmv.jku.at/picosat/picosat-965.tar.gz). You need to compile
PicoSAT with tracing enabled as a shared library under the name of
"libpicosat-trace.so", "libpicosat-trace.so.0" or "libpicosat-trace.so.1".
Tracing can be enabled using the `configure.sh` script with the `--trace`
option.
			  )"""");
}
