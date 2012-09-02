#!/usr/bin/python
#-*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# This file is a plugin for Anki flashcard application http://ichi2.net/anki/
# ---------------------------------------------------------------------------
# File:        passwords.py
# Description: This plugin uses PyMe and hashlib to attempt to securely allow
#              you to learn your passwords using Anki. The plaintext is stored
#              GPG encrypted so that it cannot be accessed. Your guesses are
#              checked against the SHA1 sum, and if you get it wrong you get
#              the option to decrypt and display the real password.
#
#              You can add passwords using a menu option in the Tools menu.
#
#              Note that I neither know Python, PyMe, anki /nor/ Hashlib, so
#              almost certainly something I've done here is stupid. The code
#              is basically based on the encrypt-to-all PyMe example with the
#              Anki stuff taken from the Go Problem, yesno and two step answer
#              plugins. Feel free to fix it and mail me the result. I certainly
#              won't be offended if you tell me my code is awful!
#
#              You will want to alter the constants at the start - at the least
#              because you don't want to encrypt your passwords to be read only
#              by me.
#
# Author:      David Buckley <isreal-anki-passwords@bucko.me.uk>
# Version:     0.01 (2009-04-28)
# License:     GNU GPL, version 3 or later; http://www.gnu.org/copyleft/gpl.html
# ---------------------------------------------------------------------------
# Changelog:
# ---- 0.02 -- 2009-04-28 -- David Buckley ----
#   fixed bug which meant password entries were corrupted on edit
# ---- 0.01 -- 2009-04-28 -- David Buckley ----
#   initial release
# ---------------------------------------------------------------------------

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from ankiqt import mw
from anki.cards import Card
from anki.models import Model, FieldModel, CardModel
from anki.errors import FactInvalidError
from anki.hooks import wrap
from ankiqt.ui import view
from ankiqt.ui import main
from pyme import core
from pyme.core import Data, Context
from pyme.constants import validity
from pyme.errors import GPGMEError
import re
import hashlib
import hmac
import os

""" You may wish to change these. """
MODEL="Password Model"
SHOW_PASS_KEY=Qt.Key_S
GPG_USER_NAME="David Buckley"
SALT=u'This is where you should put your own salt'
HASH='sha256'

def configDir():
	dirName = os.path.join(str(QDesktopServices.storageLocation(QDesktopServices.DataLocation)), "plugins/password")
	try:
		os.makedirs(dirName)
	except:
		pass
	print "Passwords config location:", dirName
	return dirName

class Config(object):
	def __init__(self):
		self.dirName = configDir()
		self.key = None
		self.gpg_user_name = None
		self.loaded = False

	def load(self):
		loaded = True
		namePath = os.path.join(self.dirName, "gpg_name")
		if os.path.exists(namePath):
			self.gpg_name = open(namePath).read()
		else:
			self.gpg_name = None
			loaded = False

		keyPath = os.path.join(self.dirName, "key")
		if os.path.exists(keyPath):
			self.key = open(keyPath).read()
		else:
			print "Passwords: GENERATING NEW KEY"
			self.key = os.urandom(hashlib.new(HASH).digest_size)
			if self.key:
				open(keyPath, "w").write(self.key)

		self.loaded = loaded

	def save_name(self):
		namePath = os.path.join(self.dirName, "gpg_name")
		if self.gpg_name:
			open(namePath, "w").write(self.gpg_name)

config = Config()

""" This routine is called after showAnswerButton, and fixes the edit box to
    hide typed text. """
def afterShowAnswerButton(self):
	if self.currentCard.fact.model.name == MODEL:
		self.typeAnswerField.setEchoMode(QLineEdit.Password)
		self.typeAnswerField.setText("")
	else:
		self.typeAnswerField.setEchoMode(QLineEdit.Normal)

""" This routine is called instead of drawAnswer, and removes the ugly SHA1
    sum, replacing it with a status message. """
def aroundDrawAnswer(self, _old=''):
	if self.main.currentCard.fact.model.name == MODEL:
		possible_macs = [ s[5:] for s in self.main.currentCard.fact.keys() if s[:5] == 'HMAC_' ]
		if possible_macs:
			my_hash_fn = possible_macs[0]
			stored_hash = self.main.currentCard.fact['HMAC_%s' % my_hash_fn]
			my_hash = unicode(hmac.new(config.key, unicode(self.main.typeAnswerField.text()).encode('utf-8'), getattr(hashlib, my_hash_fn)).hexdigest())
		else:
			# TODO should really be converting the full database by re-encrypting
			# This clause is a fallback for cards made using the old model.
			# The user will need to hard-code a SALT.
			stored_hash = self.main.currentCard.fact['SHA1']
			d = hashlib.new('sha1')
			salted = SALT + unicode(self.main.typeAnswerField.text())
			self.main.typeAnswerField.setText("")
			d.update(salted.encode('utf-8').encode('base64'))
			my_hash = unicode(d.hexdigest())

		if (my_hash == stored_hash):
			self.write(self.center('<span id=answer />' + self.mungeQA(self.main.deck, "Correct!")))
		else:
			self.write(self.center('<span id=answer />' + self.mungeQA(self.main.deck, "Wrong! Press S to decrypt and show password.")))
	else:
		_old(self)

""" Ask for a GPG password using a QInputDialog. """
def passCallback(hint='', desc='', prev_bad='', hook=''):
	extra = ''
	if prev_bad:
		extra = "\nYou got it wrong; try again."
	passphrase = str(QInputDialog.getText(mw, "GPG Passphrase", "I need your passphrase.\nKey: " + desc + "\nHint: " + hint + extra, QLineEdit.Password)[0])
	return passphrase

""" Steal presses of the SHOW_PASS_KEY to make them show the password. """
def aroundKeyPressEvent(self, evt, _old=''):
	if self.state == "showAnswer":
		key = unicode(evt.text())
		if evt.key() == SHOW_PASS_KEY:
			if self.currentCard.fact.model.name == MODEL:
				mf = self.mainWin.mainText.page().mainFrame()

				""" Set up the PyMe stuff """
				c = Context();
				c.set_passphrase_cb(passCallback)
				c.set_armor(1);
				cipher = Data(re.sub("<br[^>]*>","\n",self.currentCard.fact['GPG'].encode('ascii')))
				cipher.seek(0,0)

				""" Try to decrypt the password """
				try:
					plain = Data();
					c.op_decrypt(cipher, plain);
					plain.seek(0,0);
					QMessageBox.information(mw, "Password", "Your password is %s" % unicode(plain.read(), 'utf-8'))
				except GPGMEError, e:
					QMessageBox.information(mw, "Error", "Could not decrypt your password.\nError: " + str(e))
					
				evt.accept()
				return
	
	_old(self, evt)

def setGPGName():
	""" Set the config's GPG name for encryption """
	ret = QInputDialog.getText(mw, "Description", "Setting up passwords plugin: Enter the username to encrypt for in GPG")
	if ret[1]:
		config.gpg_name = unicode(ret[0])
		config.save_name()
	else:
		return

""" Display a sequence of dialog boxes then add a new entry to the deck """
def addPassword():
	""" Model's not there? Fix it before we get into worse trouble. """
	if not [m for m in mw.deck.models if m.name == MODEL]:
		m = Model(unicode(MODEL))
		m.addFieldModel(FieldModel(u'Description', True, True))
		m.addFieldModel(FieldModel(u'HMAC_%s' % HASH, True, True))
		m.addFieldModel(FieldModel(u'GPG', True, True))
		cm=CardModel(u'Password',u'%(Description)s',u'%%(HMAC_%s)s' % HASH)
		cm.typeAnswer = u'HMAC_%s' % HASH
		m.addCardModel(cm)
		mw.deck.addModel(m)
	else:
		m, = [m for m in mw.deck.models if m.name == MODEL]
		# Monkey patch existing models
		if 'HMAC_%s' % HASH not in [ a.name for a in m.fieldModels ]:
			m.addFieldModel(FieldModel(u'HMAC_%s' % HASH, True, True))

	ret = QInputDialog.getText(mw, "Description", "Enter a description for the password")
	if ret[1]:
		desc = unicode(ret[0])
	else:
		return

	ret = QInputDialog.getText(mw, "Password", "Enter the password", QLineEdit.Password)
	if ret[1]:
		pass1 = unicode(ret[0])
	else:
		return

	ret = QInputDialog.getText(mw, "Confirm", "Confirm the password", QLineEdit.Password)
	if ret[1]:
		pass2 = unicode(ret[0])
	else:
		return

	if pass1 != pass2:
		QMessageBox.information(mw, "Mismatch", "Your passwords didn't match")
		return

	""" Attempt to add the card. """
	try:
		fact = mw.deck.newFact()

		fact['Description'] = desc

		""" Fill in the MAC """
		mac = hmac.new(config.key, pass1.encode('utf-8'), getattr(hashlib, HASH))
		fact['HMAC_%s' % HASH] = unicode(mac.hexdigest())

		""" PyMe setup """
		c = Context();
		c.set_armor(1);
		c.op_keylist_start(GPG_USER_NAME, 0)
		key = c.op_keylist_next()

		if not key:
			QMessageBox.information(mw, "Error", "Could not find your key. Check you've set it up in the plugin file.")
			return

		print "Encrypting with key: " + key.uids[0].uid

		""" Do the encryption, or try to """
		plain = Data(pass1.encode('utf-8'))
		cipher = Data()
		try:
			c.op_encrypt([key], 1, plain, cipher)
			cipher.seek(0,0)
			fact['GPG'] = unicode(re.sub("\n","<br>",cipher.read()), 'ascii')
			mw.deck.addFact(fact)
		except GPGMEError, e:
			QMessageBox.information(mw, "Error", "Could not encrypt your password.\nError: " + str(e))

	except FactInvalidError, e:
		QMessageBox.information(mw, "Error", "Could not store your password.\nError: " + str(e))


""" Set up all the stuff we need initialising. """
def initPlugin():
	main.AnkiQt.showAnswerButton = wrap(main.AnkiQt.showAnswerButton, afterShowAnswerButton, "after")
	main.AnkiQt.keyPressEvent = wrap(main.AnkiQt.keyPressEvent, aroundKeyPressEvent, "around")
	view.View.drawAnswer = wrap(view.View.drawAnswer, aroundDrawAnswer, "around")
	menu = QAction(mw)
	menu.setText("Add Password")
	mw.connect(menu, SIGNAL("triggered()"), addPassword)
	menu2 = QAction(mw)
	menu2.setText("Set GPG User Name")
	mw.connect(menu2, SIGNAL("triggered()"), setGPGName)
	mw.mainWin.menuTools.addSeparator()
	mw.mainWin.menuTools.addAction(menu)
	mw.mainWin.menuTools.addAction(menu2)
	config.load()
	if not config.loaded:
		setGPGName()

""" Ensure we can be set up. """
mw.addHook("init", initPlugin)
