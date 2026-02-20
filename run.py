# Launch a dynamic web-server.
import http.server
import os
import socketserver

PORT = 8080


def launch_simple_http_server(port=PORT):
  Handler = http.server.SimpleHTTPRequestHandler

  os.chdir("concrete")
  with socketserver.TCPServer(("", port), Handler) as httpd:
      print(f"Serving at port {port}")
      # Start the server and keep it running until you stop the script
      httpd.serve_forever()



def launch_tornado_http_server(port=PORT):
  # python3 -m pip install tornado
  import tornado.ioloop
  import tornado.web

  class GetInTouchHandler(tornado.web.RequestHandler):
      def get(self):
        print(dir(self))
      def post(self):
        raise RuntimeError("Goodbye..")
        print(dir(self))
        self.write(f"Contacted")

  class UserHandler(tornado.web.RequestHandler):
      def get(self, username):
          # The 'username' argument comes from the regex capture group in the route
          self.write(f"Hello, user: {username}")

  ### A routes data structure is essential for dynamic services.
  routes = [
    (r"/user/([^/]+)", UserHandler),
    (r"/contact", GetInTouchHandler),
    (r"/(.*)", tornado.web.StaticFileHandler, {"path": "concrete"}),
  ]

  def make_app():
      return tornado.web.Application(routes)


  # 3. Start the server
  if __name__ == "__main__":
      app = make_app()
      app.listen(port)
      print(f"Server is running on http://localhost:{port}")
      print(f"Test dynamic route: http://localhost:{port}/user/TornadoUser")
      tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
  # launch_simple_http_server()
  launch_tornado_http_server()
  print("Goodbye.")