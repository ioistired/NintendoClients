from typing import Tuple

from nintendo.baas import BAASClient
from nintendo.dauth import DAuthClient
from nintendo.aauth import AAuthClient
from nintendo.switch import ProdInfo, KeySet
from nintendo.nex import backend, authentication, matchmaking, settings
from nintendo.games import ACNH
import anyio

import logging
logging.basicConfig(level=logging.INFO)


SYSTEM_VERSION = 1010 #10.1.0

# You can get your user id and password from
# su/baas/<guid>.dat in save folder 8000000000000010.

# Bytes 0x20 - 0x28 contain the user id in reversed
# byte order, and bytes 0x28 - 0x50 contain the
# password in plain text.

# Alternatively, you can set up a mitm on your Switch
# and extract them from the request to /1.0.0/login

BAAS_USER_ID = 0x0123456789abcdef # 16 hex digits
BAAS_PASSWORD = "..." # Should be 40 characters

# You can dump prod.keys with Lockpick_RCM and
# PRODINFO from hekate (decrypt it if necessary)
PATH_KEYS = "/path/to/prod.keys"
PATH_PRODINFO = "/path/to/PRODINFO"

# Tickets can be dumped with nxdumptool.
# You need the base ticket, not an update ticket.
# Do not remove console specific data.
PATH_TICKET = "/path/to/ticket"

CODE = "ABCDE" # Dodo code

HOST = "g%08x-lp1.s.n.srv.nintendo.net" %ACNH.GAME_SERVER_ID
PORT = 443

async def authorize() -> Tuple[int, authentication.AuthenticationInfo]:
	keys = KeySet.load(PATH_KEYS)
	info = ProdInfo(keys, PATH_PRODINFO)
	
	# This information is unique to each switch and never changes
	# If your device is ever banned, it's these keys that are revoked.
	cert = info.get_tls_cert()
	pkey = info.get_tls_key()
	
	# get a device authentication token from the dauth server
	# device_token lasts ~24 hours
	dauth = DAuthClient(keys)
	dauth.set_certificate(cert, pkey)
	dauth.set_system_version(SYSTEM_VERSION)
	response = await dauth.device_token(dauth.BAAS)
	device_token = response["device_auth_token"]
	
	# get application-specific authentication token from the AAuth server
	# app_token lasts ~24 hours
	aauth = AAuthClient()
	aauth.set_system_version(SYSTEM_VERSION)
	response = await aauth.auth_digital(
		ACNH.TITLE_ID, ACNH.LATEST_VERSION,
		device_token, ticket
	)
	app_token = response["application_auth_token"]
	
	# combine device authentication token with the user's NS Online profile information
	# to get their BAAS access token
	# access_token lasts 
	baas = BAASClient()
	baas.set_system_version(SYSTEM_VERSION)
	response = await baas.authenticate(device_token)
	access_token = response["accessToken"]
	
	response = await baas.login(
		BAAS_USER_ID, BAAS_PASSWORD, access_token, app_token
	)
	user_id = int(response["user"]["id"], 16)
	id_token = response["idToken"]
	
	auth_info = authentication.AuthenticationInfo()
	auth_info.token = id_token
	auth_info.ngs_version = 4 #Switch
	auth_info.token_type = 2
	
	return user_id, auth_info


async def main():
	user_id, auth_info = await authorize()

	s = settings.load("switch")
	s.configure(ACNH.ACCESS_KEY, ACNH.NEX_VERSION, ACNH.CLIENT_VERSION)
	async with backend.connect(s, HOST, PORT) as be:
		async with be.login(str(user_id), auth_info=auth_info) as client:
			mm = matchmaking.MatchmakeExtensionClient(client)

			param = matchmaking.MatchmakeSessionSearchCriteria()
			param.attribs = ["", "", "", "", "", ""]
			param.game_mode = "2"
			param.min_participants = "1"
			param.max_participants = "1,8"
			param.matchmake_system = "1"
			param.vacant_only = False
			param.exclude_locked = True
			param.exclude_non_host_pid = True
			param.selection_method = 0
			param.vacant_participants = 1
			param.exclude_user_password = True
			param.exclude_system_password = True
			param.refer_gid = 0
			param.codeword = CODE

			sessions = await mm.browse_matchmake_session_no_holder_no_result_range(param)
			if sessions:
				print("\nNo island found for '%s'\n" %CODE)
				return

			session = sessions[0]
			data = session.application_data
			print("\nFound island:")
			print("\tId:", session.id)
			print("\tActive players:", session.participation_count)
			print("\tIsland name:", data[12:32].decode("utf16").rstrip("\0"))
			print("\tHost name:", data[40:60].decode("utf16").rstrip("\0"))
			print()

anyio.run(main)
