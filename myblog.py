
import base
import datetime
from google.appengine.ext import db
from base import Blog
from base import User

class MainBlogHandler(base.BaseHandler):
	def get(self):  		
		items = db.GqlQuery('SELECT * FROM Blog WHERE ANCESTOR IS :1 ORDER BY datetime_modified DESC LIMIT 10', base.user_key()) 
		self.renderWithUID("homepage.html", items = items)        

class NewPostHandler(base.BaseHandler):
	def get(self):
		self.renderWithLogin('newpost.html')

	def post(self):			
		ret = self.getVerifiedPost()
		if ret:				
			blog = Blog(author = ret[0], subject = ret[1], content = ret[2], parent = base.user_key())			
			blog.put()
			self.redirect('/blog/'+str(blog.key().id()))			

class EditPostHandler(base.BaseHandler):
	def get(self):
		user, blog = self.verifyBlogUser()		
		if user:
			self.renderWithUID('newpost.html', subject = blog.subject, \
												content = blog.content.replace('<br>', '\n'))
		else:
			self.redirect('/blog')

	def post(self):
		user, blog = self.verifyBlogUser()
		if not user:
			self.redirect('/blog')
			return

		ret = self.getVerifiedPost()
		if ret:
			blog.subject = ret[1]
			blog.content = ret[2]
			
			blog.put()			
			self.redirect('/blog/'+str(blog.key().id()))

class PermLinkHandler(base.BaseHandler):
	def get(self, blog_id):		
		item = Blog.get_by_id(int(blog_id), parent=base.user_key())
		self.setSecureCookie('bid', blog_id)

		if not item:
			self.abort(404)
		else:			
			uid = self.getSecureCookie('uid')
			cur_user = User.get_by_id(int(uid), parent=base.group_key()) if uid else None			
			self.renderWithUID("permalink.html", item = item, cur_user = cur_user)

	def post(self, blog_id):
		user, blog = self.verifyBlogUser()

		if blog:
			blog.delete()
		self.redirect("/blog")
	
		