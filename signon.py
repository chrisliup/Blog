#!/usr/bin/env python

import base
import cgi
import re
import hashlib
import random
import string

from google.appengine.ext import db
from base import User

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def validateUsername(username):
	match = USER_RE.match(username)
	found = db.GqlQuery("SELECT * FROM User WHERE ANCESTOR IS :1 AND username = :2", base.group_key(), username)

	if match and found.count()==0:
		return True, 0
	if not match:
		return False, 1	
	return False, 2

def validatePassword(password):
	return PASSWORD_RE.match(password)

def validateVerify(verify, password):
	return verify == password

def validateEmail(email):
	return (not email) or EMAIL_RE.match(email)

def randomSalt(n = 5):
	return "".join([random.choice(string.ascii_letters) for x in range(n)])

def hashPassword(username, password, salt = None):
	if not salt:
		salt = randomSalt()
	return "|".join([hashlib.sha256(username+password+salt).hexdigest(), salt])

def checkPassword(username, password, passwordHash):
	salt = passwordHash.split('|')[1]
	return passwordHash == hashPassword(username, password, salt)

class SignonHandler(base.BaseHandler):
	
	def get(self):
		self.render("signon.html")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		remember_user = (self.request.get('remember_user') == "on")

		username_valid, username_status = validateUsername(username)
		password_valid = validatePassword(password)
		verify_valid = validateVerify(verify, password)
		email_valid = validateEmail(email)

		username_msg = ""
		password_msg = ""
		verify_msg = ""
		email_msg = ""

		if username_valid and password_valid and verify_valid and email_valid:
			user = User(username = username, passwordHash = hashPassword(username, password), parent = base.group_key())			
			if email:
				user.email = db.Email(email)
			
			user.put()						
			self.setSecureCookie('uid', user.key().id(), remember_cookie = remember_user)

			self.redirect("/blog/success")
		else:
			if not username_valid:
				if username_status == 1:
					username_msg = "Invalid username!"
				else:
					username_msg = "Username already exists!"

			if not password_valid:
				password_msg = "Invalid password!"
			elif not verify_valid:
				verify_msg = "Your password didn't match!"
			
			if not email_valid:
				email_msg = "Invalid Email!"

			self.render("signon.html", username = username, \
									email = email, \
									username_error = username_msg, \
									password_error = password_msg, \
									verify_error = verify_msg, \
									email_error = email_msg)
		
class LoginHandler(base.BaseHandler):
	def get(self):
		self.deleteCookie('uid')
		self.deleteCookie('bid')
		self.render("login.html")
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		remember_user = (self.request.get('remember_user') == "on")
		
		found = db.GqlQuery("SELECT * FROM User WHERE username = :1 and ANCESTOR IS :2", username, base.group_key())
		loggedin = True
		username_err_msg = ""
		password_err_msg = ""

		if found.count() == 0:
			loggedin = False
			username_err_msg = "Username doesn't exist!"
		else:
			user = found.get()
			if not checkPassword(username, password, user.passwordHash):
				loggedin = False
				password_err_msg = "Invalid pasword!"

		if loggedin:						
			self.setSecureCookie('uid', user.key().id(), remember_cookie = remember_user)
			self.redirect('/blog/success')
		else:
			self.render("login.html", username = username, \
									username_error = username_err_msg, \
									password_error = password_err_msg)

class LogoutHandler(base.BaseHandler):
	def get(self):
		self.deleteCookie('uid')
		self.redirect('/blog/login')

class SuccessHandler(base.BaseHandler):
	def get(self):
		uid = self.getSecureCookie('uid')
				
		if uid:			
			user = User.get_by_id(int(uid), parent = base.group_key())
			self.render("redirect.html", username = user.username, redirect_url = "/")
		else:
			self.redirect('/blog/signup')


