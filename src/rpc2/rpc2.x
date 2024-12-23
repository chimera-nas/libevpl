enum auth_flavor {
    AUTH_NONE       = 0,
    AUTH_SYS        = 1,
    AUTH_SHORT      = 2
};

struct authsys_parms {
    unsigned int stamp;
    string machinename<255>;
    unsigned int uid;
    unsigned int gid;
    unsigned int gids<16>;
};

struct opaque_auth {
    auth_flavor flavor;
    opaque body<400>;
};

enum msg_type {
    CALL  = 0,
    REPLY = 1
};

enum reply_stat {
    MSG_ACCEPTED = 0,
    MSG_DENIED   = 1
};

enum accept_stat {
    SUCCESS       = 0, /* RPC executed successfully             */
    PROG_UNAVAIL  = 1, /* remote hasn't exported program        */
    PROG_MISMATCH = 2, /* remote can't support version #        */
    PROC_UNAVAIL  = 3, /* program can't support procedure       */
    GARBAGE_ARGS  = 4, /* procedure can't decode params         */
    SYSTEM_ERR    = 5  /* errors like memory allocation failure */
};

enum reject_stat {
    RPC_MISMATCH = 0, /* RPC version number != 2          */
    AUTH_ERROR = 1    /* remote can't authenticate caller */
};

enum auth_stat {
    AUTH_OK           = 0,  /* success                          */
    /*
     * failed at remote end
     */
    AUTH_BADCRED      = 1,  /* bad credential (seal broken)     */
    AUTH_REJECTEDCRED = 2,  /* client must begin new session    */
    AUTH_BADVERF      = 3,  /* bad verifier (seal broken)       */
    AUTH_REJECTEDVERF = 4,  /* verifier expired or replayed     */
    AUTH_TOOWEAK      = 5,  /* rejected for security reasons    */
    /*
     * failed locally
     */
    AUTH_INVALIDRESP  = 6,  /* bogus response verifier          */
    AUTH_FAILED       = 7   /* reason unknown                   */
};

struct call_body {
    unsigned int rpcvers;       /* must be equal to two (2) */
    unsigned int prog;
    unsigned int vers;
    unsigned int proc;
    opaque_auth  cred;
    opaque_auth  verf;
};

struct mismatch_info {
    unsigned int low;
    unsigned int high;
};

union reply_data switch (accept_stat stat) {
    case SUCCESS:
        void;
    case PROG_MISMATCH:
        mismatch_info info;
    default:
        void;
};

struct accepted_reply {
    opaque_auth verf;
    reply_data  reply_data;
};


union rejected_reply switch (reject_stat stat) {
case RPC_MISMATCH:
    mismatch_info info;
case AUTH_ERROR:
    auth_stat auth;
};

union reply_body switch (reply_stat stat) {
case MSG_ACCEPTED:
    accepted_reply areply;
case MSG_DENIED:
    rejected_reply rreply;
};

union msg_body switch (msg_type mtype) {
    case CALL:
        call_body cbody;
    case REPLY:
        reply_body rbody;
};

struct rpc_msg {
    unsigned int xid;
    msg_body     body;
};
