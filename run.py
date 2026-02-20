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

if __name__ == "__main__":
  launch_simple_http_server()
  print("Goodbye.")