/**
	Parsing of command line arguments.

	Copyright: © 2012 RejectedSoftware e.K.
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
	Authors: Sönke Ludwig
*/
module vibe.core.args;

import vibe.core.log;
import vibe.data.json;
import vibe.http.server;

import std.getopt;
import std.exception;
import std.file;
import std.string;


version(Posix)
{
	import core.sys.posix.unistd;
	import core.sys.posix.pwd;

	static if( __traits(compiles, {import core.sys.posix.grp;}) ){
		import core.sys.posix.grp;
	} else {
		extern(C){
			struct group
			{
				char*   gr_name;
				char*   gr_passwd;
				gid_t   gr_gid;
				char**  gr_mem;
			}
			group* getgrnam(in char*);
		}
	}

	private enum configPath = "/etc/vibe/vibe.conf";

	private bool setUID(int uid, int gid)
	{
		if( geteuid() == 0 && (uid >= 0 || gid >= 0) ){
			logInfo("Vibe was run as root, lowering privileges to uid=%d, gid=%d...", uid, gid);
			if( gid >= 0 && setegid(gid) != 0 ) return false;
			//if( initgroups(const char *user, gid_t group);
			if( uid >= 0 && seteuid(uid) != 0 ) return false;
		}
		return true;
	}

	private int getUID(string name)
	{
		auto pw = getpwnam(name.toStringz());
		enforce(pw !is null, "Unknown user name: "~name);
		return pw.pw_uid;
	}

	private int getGID(string name)
	{
		auto gr = getgrnam(name.toStringz());
		enforce(gr !is null, "Unknown group name: "~name);
		return gr.gr_gid;
	}
} else version(Windows){
	private enum configPath = "vibe.conf";

	private bool setUID(int uid, int gid)
	{
		assert(uid < 0 && gid < 0, "UID/GID not supported on Windows.");
		if( uid >= 0 || gid >= 0 )
			return false;
		return true;
	}

	private int getUID(string name)
	{
		assert(false, "Privilege lowering not supported on Windows.");
	}

	private int getGID(string name)
	{
		assert(false, "Privilege lowering not supported on Windows.");
	}
}


/**
	Processes the command line arguments passed to the application.

	Any argument that matches a vibe supported command switch is removed from the 'args' array.
*/
void processCommandLineArgs(ref string[] args)
{
	int uid = -1;
	int gid = -1;
	bool verbose = false;
	string disthost;
	ushort distport = 11000;

	if( exists(configPath) ){
		try {
			auto config = readText(configPath);
			auto cnf = parseJson(config);
			if( auto pv = "uid" in cnf ) uid = pv.type == Json.Type.String ? getUID(pv.get!string) : pv.get!int;
			if( auto pv = "gid" in cnf ) gid = pv.type == Json.Type.String ? getUID(pv.get!string) : pv.get!int;
		} catch(Exception e){
			logWarn("Failed to parse config file %s: %s", configPath, e.msg);
		}
	} else {
		logDebug("No config file found at %s", configPath);
	}

	getopt(args,
		"uid", &uid,
		"gid", &gid,
		"verbose|v", &verbose,
		"disthost|d", &disthost,
		"disport", &distport
		);

	if( verbose ) setLogLevel(LogLevel.Trace);

	setVibeDistHost(disthost, distport);
	startListening();

	enforce(setUID(uid, gid), "Error lowering privileges!");
}
