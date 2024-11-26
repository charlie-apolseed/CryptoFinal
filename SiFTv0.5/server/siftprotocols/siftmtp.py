#python3

import os
import socket
import time
from Crypto.Cipher import AES
from . import rsa_generation

class SiFT_MTP_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		self.sqn = 1
		self.transfer_key = ""
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x10\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.rsv = b'\x00\x00'
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket

	def set_transfer_key(self, key):
		self.transfer_key = key

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i= msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'] = msg_hdr[i:]
		return parsed_msg_hdr

	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
  
		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)


		

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		nonce = msg_hdr[6:14]

		if (parsed_msg_hdr['typ'] == self.type_login_req) :
			try:
				msg_enc_tk = msg_body[-256:]
				msg_mac = msg_body[-268:-256]
				msg_enc_payload = msg_body[:-268]
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to break down message body --> ' + e.err_msg)

			tk = rsa_generation.decrypt(msg_enc_tk)
			#DEBUG 
			print("Recieved TK: " + str(tk))
			print("Recieved Nonce: " + str(nonce))
			#DEBUG 
			
			cipher = AES.new(tk, AES.MODE_GCM, nonce, mac_len=12)
			cipher.update(msg_hdr)
			try:
				decryptedPayload = cipher.decrypt_and_verify(msg_enc_payload, msg_mac) 
			except e:
				raise SiFT_MTP_Error('MAC value does not match recieved message --> ' + e.err_msg)

			self.transfer_key = tk
		else:
			try:
				msg_mac = msg_body[-12:]
				msg_enc_payload = msg_body[:-12]
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to break down login response body --> ' + e.err_msg)
			print(nonce)
			cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce, mac_len=12)
			cipher.update(msg_hdr)
			try:
				print("Recieved msg mac:")
				print(msg_mac)
				decryptedPayload = cipher.decrypt_and_verify(msg_enc_payload, msg_mac) 
				#DEBUG
				print("The message is authentic:", decryptedPayload)
				#DEBUG
			except:
				raise SiFT_MTP_Error('MAC value does not match recieved message --> ' + e.err_msg)

		return parsed_msg_hdr['typ'], decryptedPayload


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		

  
		if (msg_type == self.type_login_req) :
			MSG_MAC_LEN = 12  
			MSG_ENC_TK_LEN = 256

			rnd = os.urandom(6)
			#Calculate length of header
			msg_len = self.size_msg_hdr + len(msg_payload) + MSG_MAC_LEN + MSG_ENC_TK_LEN
			msg_len_hex = msg_len.to_bytes(2, byteorder='big')
   
			#Construct the header
			msgHeader = self.msg_hdr_ver + msg_type + msg_len_hex + self.sqn.to_bytes(2, byteorder='big') + rnd + self.rsv
			#DEBUG
			if self.DEBUG:
				print("Header: ")
				print(msgHeader.hex())
				print("Unencrypted message: ")
				print(msg_payload)
			
			#DEBUG

			#Encrypt the payload in AES-GCM
			tk = os.urandom(32) 	
			nonce = self.sqn.to_bytes(2, byteorder='big') + rnd
			cipher = AES.new(tk, AES.MODE_GCM, nonce, mac_len=12)
			cipher.update(msgHeader)
			encrytptedPayload, tag = cipher.encrypt_and_digest(msg_payload) 

			#Encrypt the tk in RSA 
			rsa_generation.generate_keypair()
			encryptedTK = rsa_generation.encrypt(tk)
			completeMessage = msgHeader + encrytptedPayload + tag + encryptedTK
   
   			#DEBUG
			if self.DEBUG:
				complete_msg_size = len(completeMessage)
				print('MTP login message to send (' + str(complete_msg_size) + '):')
				print('HDR (' + str(len(msgHeader)) + '): ' + msgHeader.hex())
				print('MSG (' + str(len(completeMessage)) + '): ')
				print(completeMessage.hex())
				print('------------------------------------------')
			#DEBUG

			try:
				self.send_bytes(completeMessage)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
		else:
			MSG_MAC_LEN = 12  
			rnd = os.urandom(6)
			msg_len = self.size_msg_hdr + len(msg_payload) + MSG_MAC_LEN
			msg_len_hex = msg_len.to_bytes(2, byteorder='big')
			#Build header
			msgHeader = self.msg_hdr_ver + msg_type + msg_len_hex + self.sqn.to_bytes(2, byteorder='big') + rnd + self.rsv
			#DEBUG
			if self.DEBUG:
				print("Header: ")
				print(msgHeader.hex())
				print("Unencrypted message: ")
				print(msg_payload)
			#DEBUG
			nonce = self.sqn.to_bytes(2, byteorder='big') + rnd
			cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce, mac_len=12)
			cipher.update(msgHeader)
			encrytptedPayload, tag = cipher.encrypt_and_digest(msg_payload) 
			completeMessage = msgHeader + encrytptedPayload + tag
			
			#DEBUG
			if self.DEBUG:
				complete_msg_size = len(completeMessage)
				print('MTP login message to send (' + str(complete_msg_size) + '):')
				print('HDR (' + str(len(msgHeader)) + '): ' + msgHeader.hex())
				print('MSG (' + str(len(completeMessage)) + '): ')
				print(completeMessage.hex())
				print('------------------------------------------')
			#DEBUG

			try:
				self.send_bytes(completeMessage)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
  
		

  
	