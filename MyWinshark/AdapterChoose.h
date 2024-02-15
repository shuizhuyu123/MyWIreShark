#pragma once

#include <QDialog>
#include <QMessageBox>
#include "ui_AdapterChoose.h"

class AdapterChoose : public QDialog
{
	Q_OBJECT

public:
	AdapterChoose(QStringList adapters,QWidget *parent = nullptr);
	void setChoose(std::function<void(QString description)> fun) { this->choose = fun; };
	void setConfirm(std::function<void()> fun) { this->confirm = fun;};
	~AdapterChoose();

private:
	bool ischoose = false;
	std::function<void(QString description)>choose;
	std::function<void()>confirm;
	QString adapter;
	Ui::AdapterChooseClass ui;
};
