from socket import *
import sys
import _thread
from urllib.parse import urlparse

"""
Proxy Server for Assignment pa1_b

This server is designed to take http requests from a client, parse them and then forward it to the correct
desired destination specified by the request.  The server then takes the response and then relays it back 
to the client and now handles concerrent requests from multiple connections.

Created by: Alec Becker
Last Updated: 1/26/18
"""

def process_socket(connectionSocket):
    keepRec =True
    # begin receiving a message
    # request_partial = connectionSocket.recv(2048).decode()
    request = ""
    message_num = 1;

    # Loop until the terminator of the message has been received
    while keepRec:
        request_partial = connectionSocket.recv(2048).decode()
        request = request + request_partial
        message_num = message_num + 1
        print(request)
        if request.endswith('\r\n\r\n') or request_partial == '\r\n':
            keepRec = False

    parameters = request.split(' ')

    print(parameters)

    # response string to send back to the requesting client
    response = ""


    # make sure the correct amount of parameters have been received
    if not (len(parameters) == 3 or len(parameters) == 5):
        response = "HTTP/1.1 400 Bad Request\r\n" + "ERROR: wrong amount of parameters in request\r\n"+"\r\n"
        connectionSocket.send(response.encode())
        connectionSocket.close()
        return

    if len(parameters) == 3:

        # Check to make sure that the first parameter was get
        if parameters[0] != "GET":
            response = "HTTP/1.1 400 Bad Request\r\n" + "ERROR: Did not receive a GET request\r\n"+"\r\n"
            connectionSocket.send(response.encode())
            connectionSocket.close()
            return
        # Check to make sure the third parameter was a HTTP/1.0 request
        if parameters[2] != "HTTP/1.0\r\n\r\n":
            response = "HTTP/1.1 400 Bad Request\r\n" + "ERROR: Did not receive a HTTP/1.0 request\r\n"+"\r\n"
            connectionSocket.send(response.encode())
            connectionSocket.close()
            return

        # urlparse creates an object that can be used to put the request together
        parsedURL = urlparse(parameters[1])

        # default port
        requestPort = 80

        # if request does not use the default port, change it
        if parsedURL.port is not None:
            requestPort = parsedURL.port

        # create a socket from the proxy server to the requested server
        requestSocket = socket(AF_INET, SOCK_STREAM)
        requestSocket.connect((parsedURL.netloc, requestPort))

        # build the request strings
        if parsedURL.path is not "":
            requestString = "GET " + parsedURL.path + " HTTP/1.0\r\n" + "Host: "+ parsedURL.netloc\
                            + "\r\n" + "Connection: close\r\n" + "\r\n"

        else:
            requestString = "GET /" + " HTTP/1.0\r\n" + "Host: "+ parsedURL.netloc + "\r\n"\
                            + "Connection: close\r\n" + "\r\n"

        # send the request to the requested server
        requestSocket.send(requestString.encode())

        # receive the output from the server
        response = requestSocket.recv(1024)
        while len(response) != 0:
            connectionSocket.send(response)
            response = requestSocket.recv(1024)

        requestSocket.close()
        connectionSocket.close()


    else:
        # Check to make sure that the first parameter was get
        if parameters[0] != "GET":
            response = "HTTP/1.1 400 Bad Request\r\n" + "ERROR: Did not receive a GET request\r\n"+"\r\n"
            connectionSocket.send(response.encode())
            connectionSocket.close()
            return
        # Check to make sure the third parameter was a HTTP/1.0 request
        if parameters[2] != "HTTP/1.0\r\n":
            response = "HTTP/1.1 400 Bad Request\r\n" + "ERROR: Did not receive a HTTP/1.0 request\r\n"+"\r\n"
            connectionSocket.send(response.encode())
            connectionSocket.close()
            return
        # Check to make sure the fourth parameter is 'Host:'
        if parameters[3] != "Host:":
            response = "HTTP/1.1 400 Bad Request\r\n" + "ERROR: Did not receive a Host\r\n"+"\r\n"
            connectionSocket.send(response.encode())
            connectionSocket.close()
            return

        # Default port
        requestPort = 80

        url = parameters[4]

        # Grab the port from the request if it specified
        portSplit = parameters[4].split(":")
        if len(portSplit) != 1:
            url = portSplit[0]
            requestPort = int(portSplit[1])

        # create a socket from the proxy server to the requested server
        requestSocket = socket(AF_INET, SOCK_STREAM)
        requestSocket.connect((url, requestPort))

        # build the request strings
        requestString = parameters[0] + " " + parameters[1] + " " + parameters[2] + parameters[3] + " " + url + "\r\n" \
                        + "Connection: close\r\n" + "\r\n"

        # send the request to the requested server
        requestSocket.send(requestString.encode())

        # receive the output from the server
        response = requestSocket.recv(1024)
        while len(response) != 0:
            connectionSocket.send(response)
            response = requestSocket.recv(1024)

        requestSocket.close()
        connectionSocket.close()

if __name__ == "__main__":
    # Check for correct input from the command line start
    if len(sys.argv)> 2:
        print("you did not enter in the correct amount of arguments, please enter only a port number")
        exit(1)

    elif len(sys.argv) == 1:
        print("please enter in a port no when running the executable: ")
        exit(1)

    else:
        serverPort = int(sys.argv[1])

    # Create a server and have it begin listening
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('', serverPort))
    serverSocket.listen(1)
    print('The server is ready to receive')

    while True:

        # Wait to accept a connection
        connectionSocket, addr = serverSocket.accept()
        print('The server has received a connection')

        # Send connection to a new thread to be processed
        _thread.start_new_thread(process_socket, (connectionSocket,))

