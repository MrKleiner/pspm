import socket
import pickle
import os
import io
import argparse

try:
	from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
	import cryptography.exceptions as crypto_exceptions
except ImportError as e:
	ChaCha20Poly1305 = None
	raise e

from .jag.jag_util import (
	print_exception_framed,
	aligned_recv,
	NamedPrint,
	skt_timeout,
	FasterTimerSched,
	terminate_skt,
)




# ==============================
#            UTIL
# ==============================

class FuckedUnpicklerButtplug(NamedPrint):
	def __init__(self, *args, **kwargs):
		self.__dict__.update(kwargs)

	def __call__(self, *args, **kwargs):
		return self

	def __repr__(self):
		return '<missing pickle global>'


class FuckedUnpickler(pickle.Unpickler, NamedPrint):
	def find_class(self, module, name):
		try:
			return super().find_class(module, name)
		except (ModuleNotFoundError, AttributeError):
			self.nprint('WARNING: MISSING SHIT:', module, name)
			return FuckedUnpicklerButtplug


class AuthFail(Exception):
	pass


class InvalidKey(AuthFail):
	pass


class WrongAuthMessageLength(AuthFail):
	pass



# ==============================
#            STUFF
# ==============================

class PSPMShared(NamedPrint):
	# So basically, it can happen so that the unpickler tries
	# importing a non-existing module...
	# This makes it stfu in a fucked up way
	USE_FUCKED_UNPICKLER = True

	# The OTHER side has this many seconds
	# to read the payload sent by THIS side
	# before its connection is terminated
	MSG_SEND_TIMEOUT = 69.000

	# The OTHER side has this many seconds
	# to finish sending the payload
	# before its connection is force terminated
	MSG_RECV_TIMEOUT = 67.000

	# The OTHER side has this many seconds
	# to read the ping sent by THIS side
	# before its connection is force terminated
	PING_TIMEOUT = 69.000

	# Auth is just a regular message, which consists of random bytes.
	AUTH_MSG_LEN = 512

	# Thou who connects has this many seconds
	# to send the first message before their connection is force terminated.
	AUTH_TIMEOUT_S = 4.000

	def __init__(self, skt_raw, key, alt_timer=None):
		# The raw socket object
		self.skt_raw = skt_raw
		# 32 bytes-long encryption key
		self.key = bytes(key)
		# Replacement for threading.Timer
		self.alt_timer = alt_timer
		# Encryption object TM
		self.cipher = ChaCha20Poly1305(self.key)


	def skt_timeout(self, timeout):
		return skt_timeout(
			self.skt_raw,
			timeout,
			timer=self.alt_timer,
		)


	def send_ping(self):
		try:
			with self.skt_timeout(self.PING_TIMEOUT):
				# Payload len of 0 = ping
				self.skt_raw.sendall(
					(0).to_bytes(4, 'little')
				)

			return (True, None)
		except Exception as e:
			print_exception_framed(e)
			return (False, e)

	def send_msg(self, msg_data):
		try:
			nonce = os.urandom(12)
			main_payload = self.cipher.encrypt(
				nonce,
				pickle.dumps(msg_data),
				None
			)

			with self.skt_timeout(self.MSG_SEND_TIMEOUT):
				# The size of the pickled shit
				self.skt_raw.sendall(
					len(main_payload).to_bytes(4, 'little')
				)

				# Some mandatory cryptographic shit
				self.skt_raw.sendall(nonce)

				# The pickled shit itself
				self.skt_raw.sendall(main_payload)

			return (True, None)

		except Exception as e:
			print_exception_framed(e)
			return (False, e)

	def read_msg(self, timeout=None):
		try:
			while True:
				payload_len = int.from_bytes(
					aligned_recv(self.skt_raw, 4),
					'little'
				)

				# Tis a ping
				if payload_len <= 0:
					continue
				else:
					break

			# Read shit from the socket
			with self.skt_timeout(timeout or self.MSG_RECV_TIMEOUT):
				pickle_bytes = self.cipher.decrypt(
					# nonce
					aligned_recv(self.skt_raw, 12),

					# pickle bytes
					aligned_recv(self.skt_raw, payload_len),

					# Whatever
					None
				)

			return (
				True,

				# Eval shit from the socket and return it
				FuckedUnpickler(io.BytesIO(pickle_bytes)).load()
				if self.USE_FUCKED_UNPICKLER else
				pickle.loads(pickle_bytes)
			)

		except Exception as e:
			return (False, e)



class PSPMListener(NamedPrint):
	def __init__(self, listen_skt, key, alt_timer=None):
		self.listen_skt = listen_skt
		self.key = key
		self.alt_timer = alt_timer

	def accept(self):
		# INCOMING socket connection from OTHER side
		skt_con, skt_addr = self.listen_skt.accept()
		self.nprint('Got connection from:', skt_addr)

		# The pspm connection itself
		pspm_con = PSPMConnection(
			skt_con,
			self.key,
			self.alt_timer
		)

		# The first message in the session is just a bunch of random bytes
		# to see whether decryption errors or not.
		# (acts as bootleg auth)
		read_ok, read_data = pspm_con.read_msg(PSPMShared.AUTH_TIMEOUT_S)

		# Error should be present in this case
		if not read_ok:
			terminate_skt(skt_con)

			if isinstance(read_data, crypto_exceptions.InvalidTag):
				raise InvalidKey('Decryption failed')
			elif isinstance(read_data, Exception):
				raise read_data
			else:
				raise AuthFail(f'Generic failure: {read_ok}')

		# Auth message has to be of specific length
		if len(read_data) != PSPMShared.AUTH_MSG_LEN:
			terminate_skt(skt_con)

			raise WrongAuthMessageLength(
				f'Wrong auth message length: Need {PSPMShared.AUTH_MSG_LEN}, '
				f'but got {len(read_data)}'
			)

		return pspm_con



class PSPMConnection(PSPMShared):
	pass



class PySecurePickleMessaging(NamedPrint):
	# Use a SUPPOSEDLY more performant version of threading.Timer
	USE_ALT_TIMER = True

	def __init__(self, key):
		self.key = bytes(key)

		self.alt_timers_sched = (
			FasterTimerSched() if self.USE_ALT_TIMER else None
		)

		self.alt_timer = (
			self.alt_timers_sched.timer if self.alt_timers_sched else None
		)

	@classmethod
	def generic_socket(cls):
		skt = socket.socket(
			socket.AF_INET,
			socket.SOCK_STREAM
		)

		skt.setsockopt(
			socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
		)

		return skt

	def listener(self, bind_addr, max_clients=69):
		# LISTEN socket, which can give birth to MULTIPLE PSPM sessions
		listen_skt = self.generic_socket()
		listen_skt.bind(bind_addr)
		listen_skt.listen(max_clients)

		return PSPMListener(
			listen_skt,
			self.key,
			alt_timer=self.alt_timer
		)

	def sender(self, tgt_addr):
		# OUTCOMING connection to OTHER side
		listen_skt = self.generic_socket()
		listen_skt.connect(tgt_addr)

		# The pspm connection itself
		pspm_con = PSPMConnection(
			listen_skt,
			self.key,
			alt_timer=self.alt_timer
		)

		# The first message in the session is just a bunch of random bytes
		# to see whether decryption errors or not.
		# (acts as bootleg auth)
		auth_ok, auth_error = pspm_con.send_msg(
			os.urandom(PSPMShared.AUTH_MSG_LEN)
		)

		# If auth failed - the connection should be closed by now
		ping_ok, ping_error = pspm_con.send_ping()

		if not ping_ok:
			raise AuthFail('Post-auth ping failed')

		return pspm_con






