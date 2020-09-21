#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "CDetour/detours.h"
#include "memoryutils.h"
#include <sourcehook/sourcehook.h>
#include <sourcehook/sourcehook_impl.h>

#define OVERRIDE override

#include "interface.h"
#include "engine/iserverplugin.h"
#include "tier0/icommandline.h"
#include "icvar.h"
#include "tier1/tier1.h"
#include "tier1/convar.h"
#include "tier1/netadr.h"
#include "tier1/utlmap.h"
#include "tier1/utlvector.h"
#include "tier1/utlbuffer.h"
#define FOR_EACH_VEC_BACK( vecName, iteratorName ) \
	for ( int iteratorName = (vecName).Count()-1; iteratorName >= 0; iteratorName-- )
#include "tokenset.h"
#pragma GCC diagnostic ignored "-Wreorder"
unsigned int GetIPNetworkByteOrder(const netadr_t &a)
{
	return *(unsigned int *)&a.ip;
}
unsigned int GetIPHostByteOrder(const netadr_t &a)
{
	return BigDWord( GetIPNetworkByteOrder(a) );
}
#include "ns_address.h"

#include "inetsupport.h"
#include "steam/steam_api.h"
#include "steam/isteamfriends.h"
#include "steam/isteamuser.h"

#define VALVE_CALLBACK_PACK_SMALL
struct SteamIPAddress_t;
#define STEAM_DEFINE_USER_INTERFACE_ACCESSOR( a1, a2, a3 )
#define k_iSteamNetworkingCallbacks 1200
using AppId_t = int;
using HAuthTicket = int;
enum EBeginAuthSessionResult : int;
enum EUserHasLicenseForAppResult : int;
enum SteamAPICall_t : int;
#include "isteamgameserver.h"
#include "isteamnetworking.h"

#include "tier0/memdbgon.h"

class CEmptyServerPlugin: public IServerPluginCallbacks
{
public:
	virtual bool			Load(	CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory );
	virtual void			Unload( void ) {}
	virtual void			Pause( void ) {}
	virtual void			UnPause( void ) {}
	virtual const char     *GetPluginDescription( void ) { return "random_map"; }
	virtual void			LevelInit( char const *pMapName ) {}
	virtual void			ServerActivate( edict_t *pEdictList, int edictCount, int clientMax ) {}
	virtual void			GameFrame( bool simulating );
	virtual void			LevelShutdown( void ) {}
	virtual void			ClientActive( edict_t *pEntity ) {}
	virtual void			ClientDisconnect( edict_t *pEntity ) {}
	virtual void			ClientPutInServer( edict_t *pEntity, char const *playername ) {}
	virtual void			SetCommandClient( int index ) {}
	virtual void			ClientSettingsChanged( edict_t *pEdict ) {}
	virtual PLUGIN_RESULT	ClientConnect( bool *bAllowConnect, edict_t *pEntity, const char *pszName, const char *pszAddress, char *reject, int maxrejectlen ) { return PLUGIN_CONTINUE; }
	virtual PLUGIN_RESULT	ClientCommand( edict_t *pEntity, const CCommand &args )  { return PLUGIN_CONTINUE; }
	virtual PLUGIN_RESULT	NetworkIDValidated( const char *pszUserName, const char *pszNetworkID )  { return PLUGIN_CONTINUE; }
	virtual void			OnQueryCvarValueFinished( QueryCvarCookie_t iCookie, edict_t *pPlayerEntity, EQueryCvarValueStatus eStatus, const char *pCvarName, const char *pCvarValue ) {}
	virtual void			OnEdictAllocated( edict_t *edict ) {}
	virtual void			OnEdictFreed( const edict_t *edict  ) {}

	CEmptyServerPlugin() :
	m_callbackCreateLobby(this, &CEmptyServerPlugin::OnCreateLobby),
	m_callbackCreateGameLobby(this, &CEmptyServerPlugin::OnCreateGameLobby)
	{}

	STEAM_CALLBACK( CEmptyServerPlugin, OnCreateLobby, LobbyCreate_t, m_callbackCreateLobby );
	STEAM_CALLBACK( CEmptyServerPlugin, OnCreateGameLobby, LobbyGameCreated_t, m_callbackCreateGameLobby );
};

#define INTERFACEVERSION_ISERVERPLUGINCALLBACKS_VERSION_3	"ISERVERPLUGINCALLBACKS003"

INetSupport *g_pNetSupport = nullptr;

CEmptyServerPlugin g_EmtpyServerPlugin;
EXPOSE_SINGLE_INTERFACE_GLOBALVAR(CEmptyServerPlugin, IServerPluginCallbacks, INTERFACEVERSION_ISERVERPLUGINCALLBACKS_VERSION_3, g_EmtpyServerPlugin);

class CCvar
{
public:
	static void Unlock(ConCommandBase *pCmd)
	{
		pCmd->m_nFlags &= ~(FCVAR_DEVELOPMENTONLY|FCVAR_HIDDEN|FCVAR_NOT_CONNECTED|FCVAR_SPONLY);
		pCmd->m_nFlags |= (FCVAR_SERVER_CAN_EXECUTE|FCVAR_CLIENTCMD_CAN_EXECUTE|FCVAR_REPLICATED);
		if(!pCmd->IsCommand()) {
			ConVar *pCvar = (ConVar *)pCmd;
			pCvar->m_bHasMin = false;
			pCvar->m_bHasMax = false;
		}
	}
	
	static ConCommandBase *GetNext(ConCommandBase *pCmd)
	{
		return pCmd->m_pNext;
	}
};

SourceHook::Impl::CSourceHookImpl g_SourceHook;
SourceHook::ISourceHook *g_SHPtr = &g_SourceHook;
int g_PLID = 0;

//ICvar *g_pCVar = nullptr;
ISteamNetworking *g_pSteamNetworking = nullptr;

class ISteamClientNew : public ISteamClient
{
public:
	virtual ISteamNetworking *GetISteamNetworking( HSteamUser hSteamUser, HSteamPipe hSteamPipe, const char *pchVersion ) = 0;
};

enum ESocketIndex_t
{
	NS_INVALID = -1,

	NS_CLIENT = 0,	// client socket
	NS_SERVER,	// server socket
#ifdef _X360
	NS_X360_SYSTEMLINK,
	NS_X360_LOBBY,
	NS_X360_TEAMLINK,
#endif
	NS_HLTV,
	NS_HLTV1, // Note: NS_HLTV1 must follow NS_HLTV, NS_HLTV2 must follow NS_HLTV1, etc.
#if defined( REPLAY_ENABLED )
	NS_REPLAY,
#endif
	MAX_SOCKETS
};

class ISteamSocketMgr
{
public:
	enum ESteamCnxType
	{
		ESCT_NEVER = 0,
		ESCT_ASBACKUP,
		ESCT_ALWAYS,

		ESCT_MAXTYPE,
	};

	enum
	{
		STEAM_CNX_PORT = 1,
	};

	virtual void Init() = 0;
	virtual void Shutdown() = 0;

	virtual ESteamCnxType GetCnxType() = 0;

	virtual void OpenSocket( int s, int nModule, int nSetPort, int nDefaultPort, const char *pName, int nProtocol, bool bTryAny ) = 0;
	virtual void CloseSocket( int s ) = 0;

	virtual int sendto( int s, const char * buf, int len, int flags, const struct sockaddr * to, int unk ) = 0;
	virtual int recvfrom( int s, char * buf, int len, int flags, struct sockaddr * from, int * unk ) = 0;

	virtual uint64 GetSteamIDForRemote( const netadr_t &remote ) = 0;
};

SH_DECL_HOOK6(ISteamSocketMgr, sendto, SH_NOATTRIB, 0, int, int, const char *, int, int, const struct sockaddr *, int);
SH_DECL_HOOK6(ISteamSocketMgr, recvfrom, SH_NOATTRIB, 0, int, int, char *, int, int, struct sockaddr *, int *);
SH_DECL_HOOK7_void(ISteamSocketMgr, OpenSocket, SH_NOATTRIB, 0, int, int, int, int, const char *, int, bool);
SH_DECL_HOOK1_void(ISteamSocketMgr, CloseSocket, SH_NOATTRIB, 0, int);
SH_DECL_HOOK1(ISteamSocketMgr, GetSteamIDForRemote, SH_NOATTRIB, 0, uint64, const netadr_t &);
SH_DECL_HOOK0(ISteamSocketMgr, GetCnxType, SH_NOATTRIB, 0, ISteamSocketMgr::ESteamCnxType);
SH_DECL_HOOK0_void(ISteamSocketMgr, Init, SH_NOATTRIB, 0);
SH_DECL_HOOK0_void(ISteamSocketMgr, Shutdown, SH_NOATTRIB, 0);

SH_DECL_HOOK0_void(ISteamGameServer, LogOnAnonymous, SH_NOATTRIB, 0);
SH_DECL_HOOK3(ISteamClient, GetISteamGameServer, SH_NOATTRIB, 0, ISteamGameServer *, HSteamUser, HSteamPipe, const char *);

static const tokenset_t< ESocketIndex_t > s_SocketIndexMap[] =
{						 
	{ "NS_CLIENT",		NS_CLIENT		},                          
	{ "NS_SERVER",		NS_SERVER		},                          
#ifdef _X360
	{ "NS_X360_SYSTEMLINK",	NS_X360_SYSTEMLINK	},
	{ "NS_X360_LOBBY",		NS_X360_LOBBY		},
	{ "NS_X360_TEAMLINK",	NS_X360_TEAMLINK	},
#endif
	{ "NS_HLTV",		NS_HLTV			},
	{ "NS_HLTV1",		NS_HLTV1		},
	{ NULL, ( ESocketIndex_t )-1 }
};

static const tokenset_t< EP2PSessionError > s_EP2PSessionErrorIndexMap[] =
{
	{ "None", k_EP2PSessionErrorNone },
	{ "Not running app", k_EP2PSessionErrorNotRunningApp },					// target is not running the same game
	{ "No rights to app", k_EP2PSessionErrorNoRightsToApp },				// local user doesn't own the app that is running
	{ "User not logged in", k_EP2PSessionErrorDestinationNotLoggedIn },		// target user isn't connected to Steam
	{ "Timeout", k_EP2PSessionErrorTimeout }
};



// Why are there two Steam P2P channels instead of one client/server channel?
//
// We use a client receive channel and a server receive channel to simulate sockets. When a user is running a listen server, ::recvfrom will be called
// simultaneously by both the server & client objects. If we were only using one channel, we would need to parse each packet received on that channel,
// determine if really intended for the callers socket, and potentially store if for another socket.

// code in this file only handles two types of sockets
static inline bool IsSteamSocketType( ESocketIndex_t eSocketType )
{
	return (eSocketType == NS_CLIENT || eSocketType == NS_SERVER);	
}

// assumes you have already called IsSteamSocketType
static inline int GetChannelForSocketType( ESocketIndex_t eSocketType )
{
	return (eSocketType == NS_CLIENT) ? INetSupport::SP2PC_RECV_CLIENT : INetSupport::SP2PC_RECV_SERVER;
}

// each virtual socket we have open to another user
class CSteamSocket
{
public:
	explicit CSteamSocket( const CSteamID &steamIdRemote, ESocketIndex_t eSocketType, const netadr_t &addr ) :
	m_steamID( steamIdRemote ), 
	m_eSocketType( eSocketType ),
	m_addr( addr )
	{}

	const CSteamID &GetSteamID() const { return m_steamID; }
	ESocketIndex_t GetSocketType() const { return m_eSocketType; }
	const netadr_t &GetNetAddress() const { return m_addr; }

	inline ESocketIndex_t GetRemoteSocketType() const
	{
		return ( m_eSocketType == NS_CLIENT ) ? NS_SERVER : NS_CLIENT;
	}

	inline int GetRemoteChannel() const
	{
		return GetChannelForSocketType( GetRemoteSocketType() );
	}

	inline int GetLocalChannel() const
	{
		return GetChannelForSocketType( m_eSocketType );
	}

private:
	CSteamID		m_steamID;			// SteamID of other user
	ESocketIndex_t	m_eSocketType;		// The socket type this connection was created on
	netadr_t		m_addr;				// The fake net address we have returned for this user
};

#define STEAM_CNX_COLOR Color( 255, 255, 100, 255 )

ConVar net_steamcnx_debug( "net_steamcnx_debug", "4", 0, "Show debug spew for steam based connections, 2 shows all network traffic for steam sockets." );
static ConVar net_steamcnx_enabled( "net_steamcnx_enabled", "1", FCVAR_RELEASE, "Use steam connections on listen server as a fallback, 2 forces use of steam connections instead of raw UDP." );
static ConVar net_steamcnx_allowrelay( "net_steamcnx_allowrelay", "1", FCVAR_RELEASE | FCVAR_ARCHIVE, "Allow steam connections to attempt to use relay servers as fallback (best if specified on command line:  +net_steamcnx_allowrelay 1)" );

#define OnlyUseSteamSockets() false

void SockAddrToNetAdr( const struct sockaddr *s, netadr_t *a )
{
	if (s->sa_family == AF_INET)
	{
		a->type = NA_IP;
		*(int *)&a->ip = ((const struct sockaddr_in *)s)->sin_addr.s_addr;
		a->port = ((const struct sockaddr_in *)s)->sin_port;
	}
}

void NetAdrToSockAddr (const netadr_t *a, struct sockaddr *s)
{
	memset (s, 0, sizeof(*s));

	if (a->type == NA_BROADCAST)
	{
		((struct sockaddr_in *)s)->sin_family = AF_INET;
		((struct sockaddr_in *)s)->sin_port = a->port;
		((struct sockaddr_in *)s)->sin_addr.s_addr = INADDR_BROADCAST;
	}
	else if (a->type == NA_IP)
	{
		((struct sockaddr_in *)s)->sin_family = AF_INET;
		((struct sockaddr_in *)s)->sin_addr.s_addr = *(int *)&a->ip;
		((struct sockaddr_in *)s)->sin_port = a->port;
	}
}

class CSteamSocketMgr : public ISteamSocketMgr
{
public:
	CSteamSocketMgr() : 
		m_bInitialized( false ),
		m_nNextRemoteAddress( 1 ),
		m_mapAdrToSteamSocket( 0, 0, DefLessFunc( netadr_t ) ),
		m_mapSocketToESocketType( 0, 0, DefLessFunc( int ) ),
		m_callbackP2PSessionRequest( this, &CSteamSocketMgr::OnP2PSessionRequest ),
		m_callbackP2PSessionConnectFail( this, &CSteamSocketMgr::OnP2PSessionConnectFail )
	{
	}
	~CSteamSocketMgr() {}


	virtual void Init() OVERRIDE
	{
		ISteamSocketMgr *pThis = META_IFACEPTR(ISteamSocketMgr);

		SH_CALL(pThis, &ISteamSocketMgr::Init)();

		m_bInitialized = true;
		if ( g_pSteamNetworking )
			g_pSteamNetworking->AllowP2PPacketRelay( net_steamcnx_allowrelay.GetBool() );

		RETURN_META(MRES_SUPERCEDE);
	}
	virtual void Shutdown() OVERRIDE
	{
		ISteamSocketMgr *pThis = META_IFACEPTR(ISteamSocketMgr);

		SH_CALL(pThis, &ISteamSocketMgr::Shutdown)();

		if ( !IsValid() )
			RETURN_META(MRES_SUPERCEDE);

		// Destroy remote sockets
		FOR_EACH_VEC_BACK( m_vecRemoteSockets, i )
		{
			CSteamSocket *pSocket = m_vecRemoteSockets[i];
			// this will delete pSocket
			DestroyConnection( pSocket );
		}
		m_vecRemoteSockets.RemoveAll();

		Assert( m_mapAdrToSteamSocket.Count() == 0 );
		m_mapAdrToSteamSocket.RemoveAll();
		m_mapSocketToESocketType.RemoveAll();

		m_bInitialized = false;

		RETURN_META(MRES_SUPERCEDE);
	}

	virtual ISteamSocketMgr::ESteamCnxType GetCnxType()
	{
		RETURN_META_VALUE(MRES_SUPERCEDE, (ISteamSocketMgr::ESteamCnxType)clamp( net_steamcnx_enabled.GetInt(), (int)ESCT_NEVER, (int)ESCT_MAXTYPE - 1 ));
	}

	virtual void OpenSocket( int s, int nModule, int nSetPort, int nDefaultPort, const char *pName, int nProtocol, bool bTryAny ) OVERRIDE
	{
		ISteamSocketMgr *pThis = META_IFACEPTR(ISteamSocketMgr);

		SH_CALL(pThis, &ISteamSocketMgr::OpenSocket)(s, nModule, nSetPort, nDefaultPort, pName, nProtocol, bTryAny);

		if ( !IsValid() )
			RETURN_META(MRES_SUPERCEDE);

		ESocketIndex_t eSocketType = ESocketIndex_t( nModule );

		if ( !IsSteamSocketType( eSocketType ) )
			RETURN_META(MRES_SUPERCEDE);

		// make sure we dont have a socket for this type
		FOR_EACH_MAP_FAST( m_mapSocketToESocketType, i )
		{
			if ( m_mapSocketToESocketType[i] == eSocketType )
			{
				AssertMsg1( false, "Already have a socket for this type: %s", s_SocketIndexMap->GetNameByToken( eSocketType ) );
				RETURN_META(MRES_SUPERCEDE);
			}
		}

		// save socket
		m_mapSocketToESocketType.InsertOrReplace( s, eSocketType );

		if ( net_steamcnx_debug.GetBool() )
		{
			ConColorMsg( STEAM_CNX_COLOR, "Opened Steam Socket %s ( socket %d )\n", s_SocketIndexMap->GetNameByToken( eSocketType ), s );
		}

		RETURN_META(MRES_SUPERCEDE);
	}
	virtual void CloseSocket( int s ) OVERRIDE
	{
		ISteamSocketMgr *pThis = META_IFACEPTR(ISteamSocketMgr);

		SH_CALL(pThis, &ISteamSocketMgr::CloseSocket)(s);

		if ( !IsValid() )
			RETURN_META(MRES_SUPERCEDE);

		#pragma message "what do i do about this"
		ESocketIndex_t eSocketType = NS_CLIENT;//ESocketIndex_t( nModule );
		if ( !IsSteamSocketType( eSocketType ) )
			RETURN_META(MRES_SUPERCEDE);

		if ( net_steamcnx_debug.GetBool() )
		{
			ConColorMsg( STEAM_CNX_COLOR, "Closed Steam Socket %s\n", s_SocketIndexMap->GetNameByToken( eSocketType ) );
		}

		FOR_EACH_VEC_BACK( m_vecRemoteSockets, i )
		{
			CSteamSocket *pSocket = m_vecRemoteSockets[i];
			if ( pSocket->GetSocketType() == eSocketType )
				DestroyConnection( pSocket );
		}
		
		FOR_EACH_MAP( m_mapSocketToESocketType, i )
		{
			if ( m_mapSocketToESocketType[ i ] == eSocketType )
			{
				m_mapSocketToESocketType.RemoveAt( i );
				break;
			}
		}

		RETURN_META(MRES_SUPERCEDE);
	}

	virtual int sendto( int s, const char * buf, int len, int flags, const struct sockaddr *addr, int unk) OVERRIDE
	{
		ns_address to;
		SockAddrToNetAdr(addr, &to.m_adr);

		if ( !to.IsType<netadr_t>() )
		{
			Warning( "WARNING: sendto: don't know how to send to non-IP address '%s'\n", ns_address_render( to ).String() );
			Assert( false );
			RETURN_META_VALUE(MRES_SUPERCEDE, -1);	// return socket_error
		}

		if ( IsValid() )
		{
			CSteamSocket *pSteamSocket = FindSocketForAddress( to );
			if ( pSteamSocket )
			{
				g_pSteamNetworking->SendP2PPacket( pSteamSocket->GetSteamID(), buf, len, k_EP2PSendUnreliable, pSteamSocket->GetRemoteChannel() );
				if ( net_steamcnx_debug.GetInt() >= 3 )
				{
					P2PSessionState_t p2pSessionState;
					Q_memset( &p2pSessionState, 0, sizeof( p2pSessionState ) );
					bool bSuccess = g_pSteamNetworking->GetP2PSessionState( pSteamSocket->GetSteamID(), &p2pSessionState );

					ESocketIndex_t eType = NS_INVALID;
					GetTypeForSocket( s, &eType );

					ConColorMsg( STEAM_CNX_COLOR, "  Send to %llx %u bytes on %s (status %s - %s)\n", 
						pSteamSocket->GetSteamID().ConvertToUint64(), 
						len,
						s_SocketIndexMap->GetNameByToken( eType ),
						bSuccess ? "true" : "false",
						p2pSessionState.m_bConnectionActive ? "connected" :"not connected" );
				}

				RETURN_META_VALUE(MRES_SUPERCEDE, len);
			}

			else if ( to.AsType<netadr_t>().GetPort() == STEAM_CNX_PORT )
			{
				if ( net_steamcnx_debug.GetInt() >= 1 )
				{
					ConColorMsg( STEAM_CNX_COLOR, "  Attempted to send %u bytes on unknown steam socket address %s\n", len, ns_address_render( to ).String() );
				}

				RETURN_META_VALUE(MRES_SUPERCEDE, len);
			}
		}

		if ( OnlyUseSteamSockets() )
		{
			Warning( "WARNING: sendto: CSteamSocketMgr isn't initialized and we aren't falling back to our own sockets\n");
			RETURN_META_VALUE(MRES_SUPERCEDE, -1);	// return socket_error
		}

		ISteamSocketMgr *pThis = META_IFACEPTR(ISteamSocketMgr);

		int ret = SH_CALL(pThis, &ISteamSocketMgr::sendto)(s, buf, len, flags, addr, unk);
		RETURN_META_VALUE(MRES_SUPERCEDE, ret);
	}

	virtual int recvfrom( int s, char * buf, int len, int flags, struct sockaddr *addr, int * unk ) OVERRIDE
	{
		ns_address from;
		SockAddrToNetAdr(addr, &from.m_adr);

		if ( !OnlyUseSteamSockets() )
		{
			ISteamSocketMgr *pThis = META_IFACEPTR(ISteamSocketMgr);

			int ret = SH_CALL(pThis, &ISteamSocketMgr::recvfrom)(s, buf, len, flags, addr, unk);
			if(ret) {
				RETURN_META_VALUE(MRES_SUPERCEDE, ret);
			}
		}

		if ( !IsValid() )
			RETURN_META_VALUE(MRES_SUPERCEDE, 0);

		// need to get data by socket type
		ESocketIndex_t eSocketType = NS_INVALID;
		if ( !GetTypeForSocket( s, &eSocketType ) )
			RETURN_META_VALUE(MRES_SUPERCEDE, 0);

		//
		// IPC-Steam performance optimization: don't do any IPC to P2P sockets API calls
		// if the session settings indicate that there can be no P2P communication
		//
		/*switch ( eSocketType )
		{
		case NS_CLIENT:
			// We can only be receiving P2P communication if we are a client of another
			// listen server, make sure that the session has the right data
			if ( sv.IsDedicated() )
				RETURN_META_VALUE(MRES_SUPERCEDE, 0);
			if ( sv.IsActive() )
				RETURN_META_VALUE(MRES_SUPERCEDE, 0);
			// Otherwise check how many players are connected to our session, if nobody is connected
			// then do no P2P communication with nobody
			if ( !g_pMatchFramework || !g_pMatchFramework->GetMatchSession() ||
				( g_pMatchFramework->GetMatchSession()->GetSessionSettings()->GetInt( "members/numMachines", 0 ) < 2 ) ||
				Q_stricmp( g_pMatchFramework->GetMatchSession()->GetSessionSettings()->GetString( "server/server" ), "listen" ) )
				RETURN_META_VALUE(MRES_SUPERCEDE, 0);
			break;
		case NS_SERVER:
			// Dedicated servers don't do P2P communication
			if ( sv.IsDedicated() )
				RETURN_META_VALUE(MRES_SUPERCEDE, 0);
			// If we are not running a listen server then there shouldn't be any P2P communication
			if ( !sv.IsActive() )
				RETURN_META_VALUE(MRES_SUPERCEDE, 0);
			// Otherwise check how many players are connected to our session, if nobody is connected
			// then do no P2P communication with nobody
			if ( !g_pMatchFramework || !g_pMatchFramework->GetMatchSession() ||
				( g_pMatchFramework->GetMatchSession()->GetSessionSettings()->GetInt( "members/numMachines", 0 ) < 2 ) )
				RETURN_META_VALUE(MRES_SUPERCEDE, 0);
			break;
		default:
			// There can be no P2P communication on any other socket type
			RETURN_META_VALUE(MRES_SUPERCEDE, 0);
		}*/

		uint32 cubMsg = 0;
		CSteamID steamIDRemote;

		// if no data to read, will return false
		if ( !g_pSteamNetworking->ReadP2PPacket( buf, len, &cubMsg, &steamIDRemote, GetChannelForSocketType( eSocketType ) ) || cubMsg == 0 )
			RETURN_META_VALUE(MRES_SUPERCEDE, 0);

		// We have the SteamID for a user who sent us a packet on the channel, but we dont know on what channel the sender is waiting for a response.
		// We could add the response channel to each packet, but because clients only communicate with servers, and vice versa, we can assume
		// that the sender is our opposite. This conversion is done in CSteamSocket::GetTargetSocketType()

		// could be a new connection from this user.. add if necessary
		CSteamSocket *pSocket = FindSocketForUser( eSocketType, steamIDRemote );
		if ( !pSocket )
		{
			pSocket = CreateConnection( eSocketType, steamIDRemote );
			Assert( pSocket );
		}

		// got data.. update params
		NetAdrToSockAddr(&pSocket->GetNetAddress(), addr);

		if ( net_steamcnx_debug.GetInt() >= 3 )
		{
			ConColorMsg( STEAM_CNX_COLOR, "  Received from %llx %u bytes on %s\n", steamIDRemote.ConvertToUint64(), cubMsg, s_SocketIndexMap->GetNameByToken( eSocketType ) );
		}

		RETURN_META_VALUE(MRES_SUPERCEDE, cubMsg);
	}

	virtual uint64 GetSteamIDForRemote( const netadr_t &addr ) OVERRIDE
	{
		ns_address remote;
		remote.m_adr = addr;

		const CSteamSocket *pSocket = FindSocketForAddress( remote );
		if ( pSocket )
		{
			RETURN_META_VALUE(MRES_SUPERCEDE, pSocket->GetSteamID().ConvertToUint64());
		}
		RETURN_META_VALUE(MRES_SUPERCEDE, 0ull);
	}

	// client connection state
	STEAM_CALLBACK( CSteamSocketMgr, OnP2PSessionRequest, P2PSessionRequest_t, m_callbackP2PSessionRequest );
	STEAM_CALLBACK( CSteamSocketMgr, OnP2PSessionConnectFail, P2PSessionConnectFail_t, m_callbackP2PSessionConnectFail );

	CSteamSocket *InitiateConnection( ESocketIndex_t eSocketType, const CSteamID &steamID, const byte *data, size_t len )
	{
		CSteamSocket *pSocket = CreateConnection( eSocketType, steamID );
		if ( !pSocket )
			return NULL;

		// don't have to wait for a connection to be established.. just send the packet
		if ( !g_pSteamNetworking->SendP2PPacket( pSocket->GetSteamID(), data, len, k_EP2PSendReliable, pSocket->GetRemoteChannel() ) )
		{
			DestroyConnection( eSocketType, steamID );
			return NULL;
		}

		return pSocket;
	}
	void DestroyConnection( ESocketIndex_t eSocketType, const CSteamID &steamID )
	{
		if ( !IsValid() )
			return;
		
		CSteamSocket *pSocket = FindSocketForUser( eSocketType, steamID );
		DestroyConnection( pSocket );	
	}

	void PrintStatus()
	{
		ConColorMsg( STEAM_CNX_COLOR, "SteamSocketMgr Status\n" );

		if ( !IsValid() )
		{
			ConColorMsg( STEAM_CNX_COLOR, " Invalid (no Steam3Client API?)\n");
			return;
		}

		// print socket info
		ConColorMsg( STEAM_CNX_COLOR, " %d connections\n", m_vecRemoteSockets.Count() );
		FOR_EACH_VEC( m_vecRemoteSockets, i )
		{	
			CSteamSocket *pSocket = m_vecRemoteSockets[i];

			P2PSessionState_t p2pSessionState;
			if ( !g_pSteamNetworking->GetP2PSessionState( pSocket->GetSteamID(), &p2pSessionState ) )
			{
				ConColorMsg( STEAM_CNX_COLOR, " %d %llx, failed to get session state\n", i, pSocket->GetSteamID().ConvertToUint64() );
				continue;
			}

			ConColorMsg( STEAM_CNX_COLOR, " %d %llx, type(%s), psuedoAddr(%s), connected(%s), connecting(%s), relay(%s), bytesQueued(%d), packetsQueued(%d), lasterror(%s)\n", 
				i,
				pSocket->GetSteamID().ConvertToUint64(),
				s_SocketIndexMap->GetNameByToken( pSocket->GetSocketType() ),
				pSocket->GetNetAddress().ToString(),
				p2pSessionState.m_bConnectionActive ? "yes" : "no",
				p2pSessionState.m_bConnecting ? "yes" : "no",
				p2pSessionState.m_bUsingRelay ? "yes" : "no",
				p2pSessionState.m_nBytesQueuedForSend,
				p2pSessionState.m_nPacketsQueuedForSend,
				s_EP2PSessionErrorIndexMap->GetNameByToken( (EP2PSessionError)p2pSessionState.m_eP2PSessionError ) );
		}
	}

private:
	CSteamSocket *CreateConnection( ESocketIndex_t eSocketType, const CSteamID &steamID )
	{
		if ( !IsValid() )
			return NULL;

		// if we already have a socket for this user, return that
		CSteamSocket *pSocket = FindSocketForUser( eSocketType, steamID );
		if ( pSocket )
			return pSocket;

		netadr_t adrRemote = GenerateRemoteAddress();
		ConColorMsg( STEAM_CNX_COLOR, "Generated %s for %llx\n", adrRemote.ToString(), steamID.ConvertToUint64() );

		// create
		pSocket = new CSteamSocket( steamID, eSocketType, adrRemote );
		m_mapAdrToSteamSocket.Insert( adrRemote, pSocket );
		m_vecRemoteSockets.AddToTail( pSocket );

		if ( net_steamcnx_debug.GetBool() )
		{
			ConColorMsg( STEAM_CNX_COLOR, "Created %s connection to %llx\n", s_SocketIndexMap->GetNameByToken( eSocketType ), steamID.ConvertToUint64() );
		}

		return pSocket;
	}
	void DestroyConnection( CSteamSocket *pSocket )
	{
		if ( !IsValid() || !pSocket )
			return;	

		// remove from address map & vector
		m_mapAdrToSteamSocket.Remove( pSocket->GetNetAddress() );
		//m_vecRemoteSockets.FindAndFastRemove( pSocket );
		m_vecRemoteSockets.FindAndRemove( pSocket );

		// we can close both channels with this user, as we can only talk to his server or client. If their client is talking to our server,
		// our client shouldn't be talking to their server
		g_pSteamNetworking->CloseP2PChannelWithUser( pSocket->GetSteamID(), pSocket->GetLocalChannel() );
		g_pSteamNetworking->CloseP2PChannelWithUser( pSocket->GetSteamID(), pSocket->GetRemoteChannel() );

		// log
		if ( net_steamcnx_debug.GetBool() )
		{
			ConColorMsg( STEAM_CNX_COLOR, "Destroyed %s connection to %llx\n", s_SocketIndexMap->GetNameByToken( pSocket->GetSocketType() ), pSocket->GetSteamID().ConvertToUint64() );
		}
		
		// done with socket
		delete pSocket;
	}
	
	bool GetTypeForSocket( int s, ESocketIndex_t *peType )
	{
		int i = m_mapSocketToESocketType.Find( s );
		if ( i == m_mapSocketToESocketType.InvalidIndex() )
			return false;

		*peType = m_mapSocketToESocketType[i];
		return true;
	}
	netadr_t GenerateRemoteAddress()
	{
		netadr_t ret( m_nNextRemoteAddress++, STEAM_CNX_PORT );
		return ret;
	}

	CSteamSocket *FindSocketForAddress( const ns_address &adr )
	{
		if ( !adr.IsType<netadr_t>() )
		{
			Assert( false );
			return nullptr;
		}

		int idx = m_mapAdrToSteamSocket.Find( adr.AsType<netadr_t>() );
		if ( idx == m_mapAdrToSteamSocket.InvalidIndex() )
			return NULL;
		return m_mapAdrToSteamSocket[ idx ];
	}
	CSteamSocket *FindSocketForUser( ESocketIndex_t eSocketType, const CSteamID &steamID )
	{
		FOR_EACH_VEC( m_vecRemoteSockets, i )
		{
			CSteamSocket *pSocket = m_vecRemoteSockets[i];
			if ( pSocket->GetSteamID() == steamID && pSocket->GetSocketType() == eSocketType )
				return pSocket;
		}

		return NULL;
	}

	bool IsValid()
	{
		if(!m_bInitialized) {
			//g_pSteamNetworking->AllowP2PPacketRelay( net_steamcnx_allowrelay.GetBool() );
			m_bInitialized = true;
		}

		return m_bInitialized && g_pSteamNetworking;
	}

	// For Remote clients
	CUtlVector< CSteamSocket * > m_vecRemoteSockets;
	CUtlMap< netadr_t, CSteamSocket * > m_mapAdrToSteamSocket;
	CUtlMap< int, ESocketIndex_t > m_mapSocketToESocketType;

	int			m_nNextRemoteAddress;
	bool		m_bInitialized;

public:
	static void AddHooks(ISteamSocketMgr *ptr);
};

void CSteamSocketMgr::OnP2PSessionRequest( P2PSessionRequest_t *pParam )
{
	// on listen servers, don't accept connections from others if they aren't in our matchmaking session
	/*if ( !g_pMatchFramework || !g_pMatchFramework->GetMatchSession() )
		return;

	if ( GetBaseLocalClient().IsConnected() && !sv.IsActive() )
		return;
	
	if ( !SessionMembersFindPlayer( g_pMatchFramework->GetMatchSession()->GetSessionSettings(), pParam->m_steamIDRemote.ConvertToUint64() ) )
		return;*/

	// accept all connections
	g_pSteamNetworking->AcceptP2PSessionWithUser( pParam->m_steamIDRemote );

	if ( net_steamcnx_debug.GetBool() )
	{
		ConColorMsg( STEAM_CNX_COLOR, "Accepted P2P connection with %llx\n", pParam->m_steamIDRemote.ConvertToUint64() );
	}
}

void CSteamSocketMgr::OnP2PSessionConnectFail( P2PSessionConnectFail_t *pParam )
{
	// log disconnect
	if ( net_steamcnx_debug.GetBool() )
	{
		const char *pchP2PError = s_EP2PSessionErrorIndexMap->GetNameByToken( (EP2PSessionError)pParam->m_eP2PSessionError );
		ConColorMsg( STEAM_CNX_COLOR, "Received connection fail for user %llx %s\n", pParam->m_steamIDRemote.ConvertToUint64(), pchP2PError );
	}

	// close all connections to this user
	FOR_EACH_VEC_BACK( m_vecRemoteSockets, i )
	{
		CSteamSocket *pSocket = m_vecRemoteSockets[i];
		if ( pSocket->GetSteamID() != pParam->m_steamIDRemote )
			continue;

		DestroyConnection( pSocket );
	}	
}

CSteamSocketMgr g_SteamSocketMgr;
ISteamSocketMgr *g_pSteamSocketMgr = nullptr;

void CSteamSocketMgr::AddHooks(ISteamSocketMgr *ptr)
{
	SH_ADD_HOOK(ISteamSocketMgr, Init, ptr, SH_MEMBER(&g_SteamSocketMgr, &CSteamSocketMgr::Init), false);
	SH_ADD_HOOK(ISteamSocketMgr, sendto, ptr, SH_MEMBER(&g_SteamSocketMgr, &CSteamSocketMgr::sendto), false);
	SH_ADD_HOOK(ISteamSocketMgr, recvfrom, ptr, SH_MEMBER(&g_SteamSocketMgr, &CSteamSocketMgr::recvfrom), false);
	SH_ADD_HOOK(ISteamSocketMgr, Shutdown, ptr, SH_MEMBER(&g_SteamSocketMgr, &CSteamSocketMgr::Shutdown), false);
	SH_ADD_HOOK(ISteamSocketMgr, GetCnxType, ptr, SH_MEMBER(&g_SteamSocketMgr, &CSteamSocketMgr::GetCnxType), false);
	SH_ADD_HOOK(ISteamSocketMgr, OpenSocket, ptr, SH_MEMBER(&g_SteamSocketMgr, &CSteamSocketMgr::OpenSocket), false);
	SH_ADD_HOOK(ISteamSocketMgr, CloseSocket, ptr, SH_MEMBER(&g_SteamSocketMgr, &CSteamSocketMgr::CloseSocket), false);
	SH_ADD_HOOK(ISteamSocketMgr, GetSteamIDForRemote, ptr, SH_MEMBER(&g_SteamSocketMgr, &CSteamSocketMgr::GetSteamIDForRemote), false);
}

ISteamGameServer *g_pGameServer = nullptr;

ConVar sv_glsttoken( "sv_glsttoken", "" );

bool g_binActivate = false;

void LogOnAnonymous()
{
	g_pGameServer = META_IFACEPTR(ISteamGameServer);

	//if(g_binActivate) {
		const char *str  = sv_glsttoken.GetString();
		if(str[0] != '\0') {
			g_pGameServer->LogOn(str);
		} else {
			SH_CALL(g_pGameServer, &ISteamGameServer::LogOnAnonymous)();
		}
	/*} else {
		SH_CALL(g_pGameServer, &ISteamGameServer::LogOnAnonymous)();
	}*/

	RETURN_META(MRES_SUPERCEDE);
}

ISteamGameServer *GetISteamGameServer(HSteamUser u, HSteamPipe p, const char *v)
{
	ISteamClient *pThis = META_IFACEPTR(ISteamClient);

	ISteamGameServer *ret = SH_CALL(pThis, &ISteamClient::GetISteamGameServer)(u, p, v);

	if(ret) {
		g_pGameServer = ret;

		SH_ADD_HOOK(ISteamGameServer, LogOnAnonymous, ret, SH_STATIC(LogOnAnonymous), false);
	}

	RETURN_META_VALUE(MRES_SUPERCEDE, ret);
}

#define MAX_ROUTABLE_PAYLOAD		1200	// x360 requires <= 1260, but now that listen servers can support "steam" mediated sockets, steam enforces 1200 byte limit

DETOUR_DECL_STATIC4(Initiate, netadr_t, int, sock, uint64, uSteamID, const char *, format, ..., )
{
	netadr_t adr;
	if ( uSteamID == 0ull )
	{
		Warning( "NET_InitiateSteamConnection called with uSteamID == 0\n" );
		return adr;
	}

	va_list		argptr;
	char		string[ MAX_ROUTABLE_PAYLOAD ];

	va_start( argptr, format );
	Q_vsnprintf( string, sizeof( string ), format, argptr );
	va_end( argptr );

	int length = Q_strlen( string );

	CUtlBuffer sendBuf;
	sendBuf.PutUnsignedInt( (unsigned int)-1 );
	sendBuf.Put( string, length );

	CSteamID steamID;
	steamID.SetFromUint64( uSteamID );

	if ( net_steamcnx_debug.GetBool() )
	{
		ConColorMsg( STEAM_CNX_COLOR, "Initiate %llx\n", uSteamID );
	}

	CSteamSocket *pSocket = g_SteamSocketMgr.InitiateConnection( (ESocketIndex_t)sock, steamID, (const byte *)sendBuf.Base(), sendBuf.TellPut() );
	if ( !pSocket )
	{
		Warning( "NET_InitiateSteamConnection failed to create a socket\n" );
		return adr;
	}

	adr = pSocket->GetNetAddress();
	return adr;
}

DETOUR_DECL_STATIC2(Termiante, void, int, sock, uint64, uSteamID)
{
	if ( uSteamID == 0ull )
		return;

	if ( net_steamcnx_debug.GetBool() )
	{
		ConColorMsg( STEAM_CNX_COLOR, "Terminate %llx\n", uSteamID );
	}

	g_SteamSocketMgr.DestroyConnection( (ESocketIndex_t)sock, uSteamID );
}

DETOUR_DECL_MEMBER0(Disconnect, void)
{
	DETOUR_MEMBER_CALL(Disconnect)();

	/*
	ns_address checkAdr = adr;
	if ( adr.IsLoopback() || adr.IsLocalhost() )
	{
		checkAdr.AsType<netadr_t>().SetIP( GetIPHostByteOrder(net_local_adr) );
	}

	if ( m_ListenServerSteamID != 0ull && m_Remote.Count() > 0 )
	{
		NET_TerminateSteamConnection( m_Socket, m_ListenServerSteamID );
		m_ListenServerSteamID = 0ull;
	}
	Steam3Client().CancelAuthTicket();
	*/
}

class ISteamFriendsNew : public ISteamFriends
{
public:
	virtual void ActivateGameOverlayToUser( const char *pchDialog, CSteamID steamID ) = 0;
	virtual void ActivateGameOverlayToWebPage( const char *pchURL, int eMode ) = 0;
	virtual void ActivateGameOverlayToStore( AppId_t nAppID, int eFlag ) = 0;
	virtual void SetPlayedWith( CSteamID steamIDUserPlayedWith ) = 0;
	virtual void ActivateGameOverlayInviteDialog( CSteamID steamIDLobby ) = 0;
	virtual int GetSmallFriendAvatar( CSteamID steamIDFriend ) = 0;
	virtual int GetMediumFriendAvatar( CSteamID steamIDFriend ) = 0;
	virtual int GetLargeFriendAvatar( CSteamID steamIDFriend ) = 0;
	virtual bool RequestUserInformation( CSteamID steamIDUser, bool bRequireNameOnly ) = 0;
	virtual SteamAPICall_t RequestClanOfficerList( CSteamID steamIDClan ) = 0;
	virtual CSteamID GetClanOwner( CSteamID steamIDClan ) = 0;
	virtual int GetClanOfficerCount( CSteamID steamIDClan ) = 0;
	virtual CSteamID GetClanOfficerByIndex( CSteamID steamIDClan, int iOfficer ) = 0;
	virtual uint32 GetUserRestrictions() = 0;
	virtual bool SetRichPresence( const char *pchKey, const char *pchValue ) = 0;
	virtual void ClearRichPresence() = 0;
	virtual const char *GetFriendRichPresence( CSteamID steamIDFriend, const char *pchKey ) = 0;
	virtual int GetFriendRichPresenceKeyCount( CSteamID steamIDFriend ) = 0;
	virtual const char *GetFriendRichPresenceKeyByIndex( CSteamID steamIDFriend, int iKey ) = 0;
	virtual void RequestFriendRichPresence( CSteamID steamIDFriend ) = 0;
	virtual bool InviteUserToGame( CSteamID steamIDFriend, const char *pchConnectString ) = 0;
};

ISteamFriendsNew *g_pSteamFriends = nullptr;
ISteamClientNew *g_pSteamClient = nullptr;
ISteamUser *g_pSteamUser = nullptr;
ISteamMatchmaking *g_pMatchmaking = nullptr;

CON_COMMAND( net_steamcnx_status_2, "Print status of steam connection sockets." )
{
	g_SteamSocketMgr.PrintStatus();
}

CSteamID g_Lobby;

CON_COMMAND( create_lobby, "" )
{
	CSteamID steamid;

	if(args.ArgC() == 2) {
		int i = atoi(args.Arg(1));
		if(i == 1) {
			steamid = g_pSteamUser->GetSteamID();
		} else if(i == 2) {
			steamid = g_Lobby;
		}
	}

	if(!steamid.IsValid()) {
		steamid = g_pGameServer->GetSteamID();
	}

	const char *str = steamid.Render();
	Msg("creating lobby for %s\n", str);

	g_pMatchmaking->CreateLobby(steamid.ConvertToUint64(), false);
}

CON_COMMAND( join_lobby, "" )
{
	CSteamID steamid;

	if(args.ArgC() == 2) {
		int i = atoi(args.Arg(1));
		if(i == 1) {
			steamid = g_pSteamUser->GetSteamID();
		} else if(i == 2) {
			steamid = g_Lobby;
		}
	}

	if(!steamid.IsValid()) {
		steamid = g_pGameServer->GetSteamID();
	}

	const char *str = steamid.Render();
	Msg("joining lobby %s\n", str);

	g_pMatchmaking->JoinLobby(steamid);
}

CON_COMMAND( invite_lobby, "" )
{
	CSteamID steamid_1;
	CSteamID steamid_2;

	if(args.ArgC() >= 2) {
		int i = atoi(args.Arg(1));
		if(i == 1) {
			steamid_1 = g_pSteamUser->GetSteamID();
		} else if(i == 2) {
			steamid_1 = g_Lobby;
		}
	}
	if(args.ArgC() >= 3) {
		int i = atoi(args.Arg(2));
		if(i == 1) {
			steamid_2 = g_pSteamUser->GetSteamID();
		} else if(i == 2) {
			steamid_2 = g_Lobby;
		}
	}

	if(!steamid_1.IsValid()) {
		steamid_1 = g_pGameServer->GetSteamID();
	}

	if(!steamid_2.IsValid()) {
		steamid_2 = g_pGameServer->GetSteamID();
	}

	const char *str1 = steamid_1.Render();
	const char *str2 = steamid_2.Render();
	Msg("inviting %s to %s\n", str2, str1);

	g_pMatchmaking->InviteUserToLobby(steamid_1, steamid_2);
}

CON_COMMAND( glst_login, "" )
{
	CSteamID steamid = g_pGameServer->GetSteamID();

	const char *str = steamid.Render();
	Msg("was logged in as %s\n", str);

	g_pGameServer->LogOff();

	if(args.ArgC() == 2) {
		const char *str  = args.Arg(1);
		g_pGameServer->LogOn(str);
	} else {
		SH_CALL(g_pGameServer, &ISteamGameServer::LogOnAnonymous)();
	}

	steamid = g_pGameServer->GetSteamID();
	str = steamid.Render();
	Msg("now logged in as %s\n", str);
}

CON_COMMAND( print_steamid, "" )
{
	if(args.ArgC() == 2) {
		int i = atoi(args.Arg(1));
		if(i == 1) {
			CSteamID steamid = g_pSteamUser->GetSteamID();

			const char *str = steamid.Render();
			Msg("cl - %s\n", str);
			return;
		} else if(i == 2) {
			const char *str = g_Lobby.Render();
			Msg("lb - %s\n", str);
		}
	}

	CSteamID steamid = g_pGameServer->GetSteamID();

	const char *str = steamid.Render();
	Msg("sv - %s\n", str);
}

CON_COMMAND( invite_menu, "" )
{
	CSteamID steamid;

	if(args.ArgC() == 2) {
		int i = atoi(args.Arg(1));
		if(i == 1) {
			steamid = g_pSteamUser->GetSteamID();
		} else if(i == 2) {
			steamid = g_Lobby;
		}
	}

	if(!steamid.IsValid()) {
		steamid = g_pGameServer->GetSteamID();
	}

	const char *str = steamid.Render();
	Msg("%s opening invite menu for %s\n", g_pSteamFriends->GetPersonaName(), str);

	g_pSteamFriends->ActivateGameOverlayInviteDialog(steamid);
}

CON_COMMAND( list_friends, "" )
{
	Msg("listing %s friends\n", g_pSteamFriends->GetPersonaName());

	int flags = k_EFriendFlagImmediate;

	int len = g_pSteamFriends->GetFriendCount(flags);
	for(int i = 0; i < len; i++) {
		CSteamID steamid = g_pSteamFriends->GetFriendByIndex(i, flags);
		const char *friendname = g_pSteamFriends->GetFriendPersonaName(steamid);

		const char *str = steamid.Render();
		Msg("%s - %s\n", friendname, str);
	}
}

CON_COMMAND( accept, "" )
{
	CSteamID steamid;

	if(args.ArgC() == 2) {
		int i = atoi(args.Arg(1));
		if(i == 1) {
			steamid = g_pSteamUser->GetSteamID();
		} else if(i == 2) {
			steamid = g_Lobby;
		}
	}

	if(!steamid.IsValid()) {
		steamid = g_pGameServer->GetSteamID();
	}

	const char *str = steamid.Render();
	Msg("accepting session with %s\n", str);

	g_pSteamNetworking->AcceptP2PSessionWithUser( steamid );
}

CON_COMMAND( invite, "" )
{
	if(args.ArgC() != 2) {
		Msg("missing name\n");
		return;
	}

	const char *name = g_pSteamFriends->GetPersonaName();

	const char *target = args.Arg(1);

	if(strcmp(target, "self") == 0) {
		CSteamID steamid = g_pSteamUser->GetSteamID();
		const char *str = steamid.Render();
		Msg("%s sending invite to %s - %s\n", name, name, str);

		g_pSteamFriends->InviteUserToGame(steamid, "connect p2p:");
	} else if(strcmp(target, "server") == 0) {
		CSteamID steamid = g_pGameServer->GetSteamID();
		const char *str = steamid.Render();
		Msg("%s sending invite to %s\n", name, str);

		g_pSteamFriends->InviteUserToGame(steamid, "connect p2p:");
	} else if(strcmp(target, "lobby") == 0) {
		const char *str = g_Lobby.Render();
		Msg("%s sending invite to %s\n", name, str);

		g_pSteamFriends->InviteUserToGame(g_Lobby, "connect p2p:");
	} else {
		int flags = k_EFriendFlagImmediate;

		bool invited = false;

		int len = g_pSteamFriends->GetFriendCount(flags);
		for(int i = 0; i < len; i++) {
			CSteamID steamid = g_pSteamFriends->GetFriendByIndex(i, flags);
			const char *friendname = g_pSteamFriends->GetFriendPersonaName(steamid);

			if(strcmp(target, friendname) == 0) {
				const char *str = steamid.Render();
				Msg("%s sending invite to %s - %s\n", name, friendname, str);

				g_pSteamFriends->InviteUserToGame(steamid, "connect p2p:");
				invited = true;
				break;
			}
		}

		if(!invited) {
			Msg("friend %s not found\n", target);
		}
	}
}

void CEmptyServerPlugin::OnCreateGameLobby(LobbyGameCreated_t *pParam)
{
	printf("lobby created 1\n");
}

void CEmptyServerPlugin::OnCreateLobby(LobbyCreate_t *pParam)
{
	//CSteamID owner = g_pGameServer->GetSteamID();
	//CSteamID server = g_pGameServer->GetSteamID();

	g_Lobby = pParam->m_ulSteamIDLobby;
	printf("lobby created 2\n");
	//g_pMatchmaking->SetLobbyType(pParam->m_ulSteamIDLobby, k_ELobbyTypePublic);
	//g_pMatchmaking->SetLobbyMemberLimit(pParam->m_ulSteamIDLobby, 33);
	//g_pMatchmaking->SetLobbyOwner(pParam->m_ulSteamIDLobby, owner);
	//g_pMatchmaking->SetLobbyJoinable(pParam->m_ulSteamIDLobby, true);
	//g_pMatchmaking->SetLobbyGameServer(pParam->m_ulSteamIDLobby, uint32 unGameServerIP, uint16 unGameServerPort, server);
}

void CEmptyServerPlugin::GameFrame( bool simulating )
{
	SteamAPI_RunCallbacks();
}

S_API bool SteamAPI_InitSafe();

DETOUR_DECL_MEMBER0(Activate, void)
{
	g_binActivate = true;
	DETOUR_MEMBER_CALL(Activate)();
	g_binActivate = false;

	SteamAPI_InitSafe();
}

S_API HSteamPipe SteamGameServer_GetHSteamPipe();
S_API HSteamUser SteamGameServer_GetHSteamUser();
S_API HSteamUser SteamAPI_GetHSteamUser();
S_API HSteamPipe SteamAPI_GetHSteamPipe();
S_API void * SteamInternal_CreateInterface( const char *ver );
S_API void * SteamGameServerInternal_CreateInterface( const char *ver );

bool CEmptyServerPlugin::Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory)
{
	g_pCVar = (ICvar *)interfaceFactory(CVAR_INTERFACE_VERSION, nullptr);
	g_pNetSupport = (INetSupport *)interfaceFactory(INETSUPPORT_VERSION_STRING, nullptr);

	ConVar_Register(0, nullptr);

	ICvar::Iterator it(g_pCVar);
	for(it.SetFirst(); it.IsValid(); it.Next()) {
		ConCommandBase *pCVar = it.Get();
		CCvar::Unlock(pCVar);
		pCVar = pCVar->GetNext();
	}

	ConVar *sv_hibernate_when_empty = g_pCVar->FindVar("sv_hibernate_when_empty");
	sv_hibernate_when_empty->SetValue(false);

	g_pSteamClient = (ISteamClientNew *)SteamInternal_CreateInterface( STEAMCLIENT_INTERFACE_VERSION );
	
	HSteamUser hSteamUser = SteamAPI_GetHSteamUser();
	HSteamPipe hSteamPipe = SteamAPI_GetHSteamPipe();

	g_pSteamUser = g_pSteamClient->GetISteamUser( hSteamUser, hSteamPipe, STEAMUSER_INTERFACE_VERSION );

	hSteamUser = g_pSteamUser->GetHSteamUser();

	g_pSteamNetworking = g_pSteamClient->GetISteamNetworking( hSteamUser, hSteamPipe, STEAMNETWORKING_INTERFACE_VERSION );
	g_pSteamFriends = (ISteamFriendsNew *)g_pSteamClient->GetISteamFriends( hSteamUser, hSteamPipe, STEAMFRIENDS_INTERFACE_VERSION );

	g_pMatchmaking = g_pSteamClient->GetISteamMatchmaking( hSteamUser, hSteamPipe, STEAMMATCHMAKING_INTERFACE_VERSION );

	SH_ADD_HOOK(ISteamClient, GetISteamGameServer, g_pSteamClient, SH_STATIC(GetISteamGameServer), false);

	g_pGameServer = g_pSteamClient->GetISteamGameServer( hSteamUser, hSteamPipe, STEAMGAMESERVER_INTERFACE_VERSION );

	Dl_info info;
	dladdr((void *)interfaceFactory, &info);
	void *eng = dlopen(info.dli_fname, RTLD_NOW);

	void *ptractivate = ResolveSymbol(eng, "_ZN13CSteam3Server8ActivateEv");
	DETOUR_CREATE_MEMBER(Activate, ptractivate)->EnableDetour();

	void *ptrinitiate = ResolveSymbol(eng, "_Z27NET_InitiateSteamConnectioniyPKcz");
	DETOUR_CREATE_STATIC(Initiate, ptrinitiate)->EnableDetour();

	void *ptrterminate = ResolveSymbol(eng, "_Z28NET_TerminateSteamConnectioniy");
	DETOUR_CREATE_STATIC(Termiante, ptrterminate)->EnableDetour();

	void *ptrdisconnect = ResolveSymbol(eng, "_ZN16CBaseClientState10DisconnectEb");
	DETOUR_CREATE_MEMBER(Disconnect, ptrdisconnect)->EnableDetour();

	g_pSteamSocketMgr = *(ISteamSocketMgr **)ResolveSymbol(eng, "g_pSteamSocketMgr");
	CSteamSocketMgr::AddHooks(g_pSteamSocketMgr);

	Msg("l4d-p2p loaded\n");

	return true;
}