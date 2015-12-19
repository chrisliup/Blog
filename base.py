
import os
import webapp2
import jinja2
import hmac
import datetime
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "template")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)


class Blog(db.Model):
	author = db.StringProperty(required = True)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	datetime_modified = db.DateTimeProperty(auto_now = True)
	datetime_created = db.DateTimeProperty(auto_now_add = True)	

	def render(self):
		return render_str("post.html", item = self)
	def hasattr(self, attr_name):
		return hasattr(self, attr_name)

class User(db.Model):
	username = db.StringProperty(required = True)
	passwordHash = db.StringProperty(required = True)
	email = db.EmailProperty()
	time_created = db.DateProperty(auto_now_add = True)

def group_key(Default = 'Family'):
	return db.Key.from_path('UserGroup', Default)


def user_key(username = "Yucheng_Liu"):
	return db.Key.from_path('User', username)


class Cookie:

	SECRET_STR = "Liyuan Lin"

	@classmethod
	def hashCookie(cls, cookie):	
		cookie = str(cookie)
		return "|".join([cookie, hmac.new(cls.SECRET_STR, cookie).hexdigest()])

	@classmethod
	def verifyCookie(cls, cookieHash):
		cookieHash = str(cookieHash)
		if not cookieHash:
			return False
		cookie = cookieHash.split("|")[0]	
		return cookieHash == cls.hashCookie(cookie)

	@classmethod
	def extractCookie(cls, cookieHash):
		cookieHash = str(cookieHash)
		if cls.verifyCookie(cookieHash):
			return cookieHash.split('|')[0]

class BaseHandler(webapp2.RequestHandler):
	def render(self, template, **kw):
		self.response.out.write(render_str(template, **kw))

	def renderWithUID(self, template, **kw):
		uid = self.getSecureCookie('uid')
		if uid:
			user = User.get_by_id(int(uid), parent = group_key())
			if user:
				kw['curr_user'] = user.username
		self.render(template, **kw)

	def renderWithLogin(self, template, **kw):
		uid = self.getSecureCookie('uid')
		loggedin = False
		if uid:
			user = User.get_by_id(int(uid), parent = group_key())
			if user:
				kw['curr_user'] = user.username
				loggedin = True
		if loggedin:			
			self.render(template, **kw)
		else:
			self.redirect('/blog/login')

	def getVerifiedPost(self):
		uid = self.getSecureCookie('uid')
		user = User.get_by_id(int(uid), parent = group_key()) if uid else None
		if not user:
			self.redirect("/blog/login")
			return
		
		subject = self.request.get("subject")
		content = self.request.get("content")
		subject_err_msg = ""
		content_err_msg = ""
		if not subject:
			subject_err_msg = "Subject required!"
		if not content:
			content_err_msg = "Content required!"

		if subject and content:
			content = content.replace('\n', '<br>')
			return user.username, subject, content
		else:			
			self.render("newpost.html", subject = subject, \
						content = content, \
						subject_error_msg = subject_err_msg, \
						content_error_msg = content_err_msg)
		

	def verifyBlogUser(self):
		uid = self.getSecureCookie('uid')
		bid = self.getSecureCookie('bid')
		if uid and bid:
			user = User.get_by_id(int(uid), parent = group_key())
			blog = Blog.get_by_id(int(bid), parent = user_key())			
			if user and blog and user.username == blog.author:
				return user, blog
		return None, None


	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def setSecureCookie(self, name, value, **kw):
		secureCookie = Cookie.hashCookie(value)	
		remember_cookie = kw.get('remember_cookie', False)
		future_year = datetime.datetime.now() + datetime.timedelta(days=1000)
		expires = future_year.strftime("%a, %d %b %Y %H:%M:%S UTC") if remember_cookie else ""

		self.response.headers.add_header('Set-Cookie', \
			str('%s=%s; Path=/; Expires=%s' % \
			(name, secureCookie, expires)))

	def getSecureCookie(self, name):
		cookieHash = self.request.cookies.get(name)
		return Cookie.extractCookie(cookieHash)

	def deleteCookie(self, name):
		self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % name)


