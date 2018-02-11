from socket import *
import sys
import _thread
from urllib.parse import urlparse
import hashlib
import requests

"""
Proxy Server for Assignment pa1

This server is designed to take http requests from a client, parse them and then forward it to the correct
desired destination specified by the request.  The server than takes the response sends it to totalvirus.com
via an api call and checks the response against well known malware files.  If there is no malware detected,
the file will then be forwarded on to the client.  If there is malware, the server will not forward the content
to the client and it will instead give a warning message about the content.  This server is built to withstand multiple
concurrent requests

Created by: Alec Becker
Last Updated: 2/10/18
"""


def process_malware_detection(request_response):
    m = hashlib.md5(request_response).hexdigest()
    params = {'apikey': api_key, 'resource': m}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers)
    json_response = response.json()

    print(json_response)

    return json_response


def process_socket(connectionSocket):

    keepRec =True
    badRec = False
    # begin receiving a message
    # request_partial = connectionSocket.recv(2048).decode()
    request = ""

    # Loop until the terminator of the message has been received
    while keepRec:
        try:
            request_partial = connectionSocket.recv(4096).decode("unicode_escape")
        except Exception as e: # update the time stamp
            response_message = 'HTTP/1.1 400 Bad Request\r\n\r\n' \
                               '<html>' \
                               '<head>' \
                               '<title>404 Not Found</title>' \
                               '</head>' \
                               '<body>' \
                               '<h1>Not Found</h1>' \
                               '<p>The requested URL /~kobus/simple1.html was not found on this server.</p>' \
                               '<hr>' \
                               '<address>Apache/2.4.7 (Ubuntu) Server at www.cs.utah.edu Port 80</address>' \
                               '</body>' \
                               '</html>'
            connectionSocket.send(response_message.encode())
            badRec = True
            keepRec = False

        request = request + request_partial
        if request.endswith('\r\n\r\n') or request_partial == '\r\n':
            keepRec = False

        # error decoding message so exit process
        if badRec:
            return

    print(request)

    # response string to send back to the requesting client
    response = ""

    parameters = request.split(' ')

    # Process firefox request
    if 'User-Agent: Mozilla' in request:
        # Default port
        requestPort = 80

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

        request = request.replace('Connection: keep-alive', 'Connection: close')

        # send the request to the requested server
        requestSocket.send(request.encode())

        # receive the output from the server
        partial_response = requestSocket.recv(1024)
        response = partial_response
        while len(partial_response) != 0:
            partial_response = requestSocket.recv(1024)
            response = response + partial_response

        malware_split = response.split(b'\r\n\r\n')

        if len(malware_split) >= 2:
            virus_response = process_malware_detection(malware_split[1])
            if 'positives' in virus_response:
                if virus_response['positives'] == 0:
                    connectionSocket.send(response)
                else:
                    # implement virus response to client
                    malware_detection = 'HTTP/1.0 200 OK\r\n' \
                                        'Connection: close\r\n' \
                                        '<html>' \
                                        '<head>' \
                                        '<title>MalWareDetected</title>' \
                                        '</head>' \
                                        '<body>' \
                                        '<h1>MalWare Detected</h1>' \
                                        '<p>Do Not Continue</p>' \
                                        '<hr>' \
                                        '<address>Apache/2.4.7 (Ubuntu) Server at www.cs.utah.edu Port 80</address>' \
                                        '</body>' \
                                        '</html>'
                    connectionSocket.send(malware_detection.encode())
            else:
                connectionSocket.send(response)
        else:
            connectionSocket.send(response)

        requestSocket.close()
        connectionSocket.close()

    # Process curl request
    elif 'User-Agent: curl' in request:
        # Default port
        requestPort = 80

        # urlparse creates an object that can be used to put the request together
        parsedURL = urlparse(parameters[1])

        # default port
        requestPort = 80

        # if request does not use the default port, change it
        if parsedURL.port is not None:
            requestPort = parsedURL.port

        print(parsedURL.netloc)
        print(requestPort)
        # create a socket from the proxy server to the requested server
        requestSocket = socket(AF_INET, SOCK_STREAM)

        split_on_colon = parsedURL.netloc.split(':')
        if len(split_on_colon) > 1:
            requestSocket.connect((split_on_colon[0], requestPort))
        else:
            requestSocket.connect((parsedURL.netloc, requestPort))

        replace_string = 'http://' + parsedURL.netloc
        request =  request.replace(replace_string, '')

        request = request.replace('Proxy-Connection: Keep-Alive', 'connection: close')

        # send the request to the requested server
        requestSocket.send(request.encode())

        # receive the output from the server
        response = b''

        while True:
            recievedbytes = requestSocket.recv(1024)
            response = response + recievedbytes
            if not recievedbytes:
                break


        malware_split = response.split(b'\r\n\r\n')

        print(malware_split)

        if len(malware_split) >= 2:
            virus_response = process_malware_detection(malware_split[1])
            if 'positives' in virus_response:
                if virus_response['positives'] == 0:
                    connectionSocket.send(response)
                else:
                    # implement virus response to client
                    malware_detection = 'HTTP/1.0 200 OK\r\n' \
                                        'Connection: close\r\n' \
                                        '<html>' \
                                        '<head>' \
                                        '<title>MalWareDetected</title>' \
                                        '</head>' \
                                        '<body>' \
                                        '<h1>MalWare Detected</h1>' \
                                        '<p>Do Not Continue</p>' \
                                        '<hr>' \
                                        '<address>Apache/2.4.7 (Ubuntu) Server at www.cs.utah.edu Port 80</address>' \
                                        '</body>' \
                                        '</html>'
                    connectionSocket.send(malware_detection.encode())
            else:
                connectionSocket.send(response)
        else:
            connectionSocket.send(response)

        requestSocket.close()
        connectionSocket.close()

    # Process wget request
    elif 'User-Agent: Wget' in request:
        # Default port
        requestPort = 80
        # urlparse creates an object that can be used to put the request together
        parsedURL = urlparse(parameters[1])

        # default port
        requestPort = 80

        # if request does not use the default port, change it
        if parsedURL.port is not None:
            requestPort = parsedURL.port

        # create a socket from the proxy server to the requested server
        requestSocket = socket(AF_INET, SOCK_STREAM)

        split_on_colon = parsedURL.netloc.split(':')
        if len(split_on_colon) > 1:
            requestSocket.connect((split_on_colon[0], requestPort))
        else:
            requestSocket.connect((parsedURL.netloc, requestPort))

        replace_string = 'http://' + parsedURL.netloc
        request =  request.replace(replace_string, '')
        request = request.replace('Proxy-Connection: Keep-Alive', 'connection: close')

        print(request)
        # send the request to the requested server
        requestSocket.send(request.encode())

        # receive the output from the server
        response = b''

        while True:
            recievedbytes = requestSocket.recv(1024)
            response = response + recievedbytes
            print(recievedbytes)
            if not recievedbytes:
                break
        print("here1")
        malware_split = response.split(b'\r\n\r\n')
        print("here2")
        if len(malware_split) >= 2:
            virus_response = process_malware_detection(malware_split[1])
            if 'positives' in virus_response:
                if virus_response['positives'] == 0:
                    connectionSocket.send(response)
                else:
                    # implement virus response to client
                    malware_detection = 'HTTP/1.0 200 OK\r\n' \
                                        'Connection: close\r\n' \
                                        '<html>' \
                                        '<head>' \
                                        '<title>MalWareDetected</title>' \
                                        '</head>' \
                                        '<body>' \
                                        '<h1>MalWare Detected</h1>' \
                                        '<p>Do Not Continue</p>' \
                                        '<hr>' \
                                        '<address>Apache/2.4.7 (Ubuntu) Server at www.cs.utah.edu Port 80</address>' \
                                        '</body>' \
                                        '</html>'
                    connectionSocket.send(malware_detection.encode())
            else:
                connectionSocket.send(response)
        else:
            connectionSocket.send(response)

        requestSocket.close()
        connectionSocket.close()

    # Telnet checks
    else:
        request = request.replace('\r\n', ' ')
        request = request.strip()
        parameters = request.split(' ')
        # make sure the correct amount of parameters have been received
        if not (len(parameters) == 3 or len(parameters) == 5):
            response = "HTTP/1.1 400 Bad Request\r\n" + "ERROR: wrong amount of parameters in request\r\n"+"\r\n"
            connectionSocket.send(response.encode())
            connectionSocket.close()
            return

        elif len(parameters) == 3:

            # Check to make sure that the first parameter was get
            if parameters[0] != "GET":
                response = "HTTP/1.1 400 Bad Request\r\n" + "ERROR: Did not receive a GET request\r\n"+"\r\n"
                connectionSocket.send(response.encode())
                connectionSocket.close()
                return
            # Check to make sure the third parameter was a HTTP/1.0 request
            if parameters[2] != "HTTP/1.0":
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

            split_on_colon = parsedURL.netloc.split(':')
            if len(split_on_colon) > 1:
                print(split_on_colon)
                requestSocket.connect((split_on_colon[0], requestPort))
            else:
                print(parsedURL.netloc)
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
            response = b''

            while True:
                recievedbytes = requestSocket.recv(1024)
                response = response + recievedbytes
                if not recievedbytes:
                    break
            # Get the body of the message so you can run it through the malware detector
            malware_split = response.split(b'\r\n\r\n')

            if len(malware_split) >= 2:
                virus_response = process_malware_detection(malware_split[1])
                if 'positives' in virus_response:
                    if virus_response['positives'] == 0:
                        connectionSocket.send(response)
                    else:
                        # implement virus response to client
                        malware_detection = 'HTTP/1.0 200 OK\r\n' \
                                            'Connection: close\r\n' \
                                            '<html>' \
                                            '<head>' \
                                            '<title>MalWareDetected</title>' \
                                            '</head>' \
                                            '<body>' \
                                            '<h1>MalWare Detected</h1>' \
                                            '<p>Do Not Continue</p>' \
                                            '<hr>' \
                                            '<address>Apache/2.4.7 (Ubuntu) Server at www.cs.utah.edu Port 80</address>' \
                                            '</body>' \
                                            '</html>'
                        connectionSocket.send(malware_detection.encode())
                else:
                    connectionSocket.send(response)
            else:
                connectionSocket.send(response)

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
            if parameters[2] != "HTTP/1.0":
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
            requestString = parameters[0] + " " + parameters[1] + " " + parameters[2] +"\r\n" + parameters[3] + " " + url + "\r\n" \
                            + "Connection: close\r\n" + "\r\n"

            # send the request to the requested server
            requestSocket.send(requestString.encode())

            # receive the output from the server
            response = b''

            while True:
                recievedbytes = requestSocket.recv(1024)
                response = response + recievedbytes
                if not recievedbytes:
                    break

            malware_split = response.split(b'\r\n\r\n')

            if len(malware_split) >= 2:
                virus_response = process_malware_detection(malware_split[1])
                if 'positives' in virus_response:
                    if virus_response['positives'] == 0:
                        connectionSocket.send(response)
                    else:
                        # implement virus response to client
                        malware_detection = 'HTTP/1.0 200 OK\r\n' \
                                            'Connection: close\r\n' \
                                            '<html>' \
                                            '<head>' \
                                            '<title>MalWareDetected</title>' \
                                            '</head>' \
                                            '<body>' \
                                            '<h1>MalWare Detected</h1>' \
                                            '<p>Do Not Continue</p>' \
                                            '<hr>' \
                                            '<address>Apache/2.4.7 (Ubuntu) Server at www.cs.utah.edu Port 80</address>' \
                                            '</body>' \
                                            '</html>'
                        connectionSocket.send(malware_detection.encode())
                else:
                    connectionSocket.send(response)
            else:
                connectionSocket.send(response)

            requestSocket.close()
            connectionSocket.close()

if __name__ == "__main__":
    # Check for correct input from the command line start
    api_key = ""
    if len(sys.argv) != 3:
        print("you did not enter in the correct amount of arguments, please enter only a port number and one API Key")
        exit(1)

    else:
        serverPort = int(sys.argv[1])
        api_key = sys.argv[2]

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


