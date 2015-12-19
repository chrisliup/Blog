#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import datetime

import base
import myblog
import signon
import webapp2


class MainHandler(base.BaseHandler):
	def get(self):
		self.redirect('/blog')


app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/blog', myblog.MainBlogHandler),
	('/blog/newpost', myblog.NewPostHandler),
	('/blog/editpost', myblog.EditPostHandler),
	('/blog/(\d+)', myblog.PermLinkHandler),
	('/blog/signup', signon.SignonHandler),
	('/blog/success', signon.SuccessHandler),
	('/blog/login', signon.LoginHandler),
	('/blog/logout', signon.LogoutHandler)
], debug=True)
