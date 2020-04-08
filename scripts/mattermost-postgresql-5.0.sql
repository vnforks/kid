--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: audits; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.audits (
    id character varying(26) NOT NULL,
    createat bigint,
    userid character varying(26),
    action character varying(512),
    extrainfo character varying(1024),
    ipaddress character varying(64),
    sessionid character varying(26)
);


ALTER TABLE public.audits OWNER TO kuser;

--
-- Name: classmemberhistory; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.classmemberhistory (
    classid character varying(26) NOT NULL,
    userid character varying(26) NOT NULL,
    jointime bigint NOT NULL,
    leavetime bigint
);


ALTER TABLE public.classmemberhistory OWNER TO kuser;

--
-- Name: classmembers; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.classmembers (
    classid character varying(26) NOT NULL,
    userid character varying(26) NOT NULL,
    roles character varying(64),
    lastviewedat bigint,
    msgcount bigint,
    mentioncount bigint,
    notifyprops character varying(2000),
    lastupdateat bigint,
    schemeuser boolean,
    schemeadmin boolean
);


ALTER TABLE public.classmembers OWNER TO kuser;

--
-- Name: classes; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.classes (
    id character varying(26) NOT NULL,
    createat bigint,
    updateat bigint,
    deleteat bigint,
    branchid character varying(26),
    type character varying(1),
    displayname character varying(64),
    name character varying(64),
    header character varying(1024),
    purpose character varying(250),
    lastpostat bigint,
    totalmsgcount bigint,
    extraupdateat bigint,
    creatorid character varying(26),
    schemeid character varying(26)
);


ALTER TABLE public.classes OWNER TO kuser;

--
-- Name: clusterdiscovery; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.clusterdiscovery (
    id character varying(26) NOT NULL,
    type character varying(64),
    clustername character varying(64),
    hostname character varying(512),
    gossipport integer,
    port integer,
    createat bigint,
    lastpingat bigint
);


ALTER TABLE public.clusterdiscovery OWNER TO kuser;

--
-- Name: commands; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.commands (
    id character varying(26) NOT NULL,
    token character varying(26),
    createat bigint,
    updateat bigint,
    deleteat bigint,
    creatorid character varying(26),
    branchid character varying(26),
    trigger character varying(128),
    method character varying(1),
    username character varying(64),
    iconurl character varying(1024),
    autocomplete boolean,
    autocompletedesc character varying(1024),
    autocompletehint character varying(1024),
    displayname character varying(64),
    description character varying(128),
    url character varying(1024)
);


ALTER TABLE public.commands OWNER TO kuser;

--
-- Name: commandwebhooks; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.commandwebhooks (
    id character varying(26) NOT NULL,
    createat bigint,
    commandid character varying(26),
    userid character varying(26),
    classid character varying(26),
    rootid character varying(26),
    parentid character varying(26),
    usecount integer
);


ALTER TABLE public.commandwebhooks OWNER TO kuser;

--
-- Name: compliances; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.compliances (
    id character varying(26) NOT NULL,
    createat bigint,
    userid character varying(26),
    status character varying(64),
    count integer,
    "desc" character varying(512),
    type character varying(64),
    startat bigint,
    endat bigint,
    keywords character varying(512),
    emails character varying(1024)
);


ALTER TABLE public.compliances OWNER TO kuser;

--
-- Name: emoji; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.emoji (
    id character varying(26) NOT NULL,
    createat bigint,
    updateat bigint,
    deleteat bigint,
    creatorid character varying(26),
    name character varying(64)
);


ALTER TABLE public.emoji OWNER TO kuser;

--
-- Name: fileinfo; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.fileinfo (
    id character varying(26) NOT NULL,
    creatorid character varying(26),
    postid character varying(26),
    createat bigint,
    updateat bigint,
    deleteat bigint,
    path character varying(512),
    thumbnailpath character varying(512),
    previewpath character varying(512),
    name character varying(256),
    extension character varying(64),
    size bigint,
    mimetype character varying(256),
    width integer,
    height integer,
    haspreviewimage boolean
);


ALTER TABLE public.fileinfo OWNER TO kuser;

--
-- Name: incomingwebhooks; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.incomingwebhooks (
    id character varying(26) NOT NULL,
    createat bigint,
    updateat bigint,
    deleteat bigint,
    userid character varying(26),
    classid character varying(26),
    branchid character varying(26),
    displayname character varying(64),
    description character varying(128),
    username text,
    iconurl text,
    classlocked boolean
);


ALTER TABLE public.incomingwebhooks OWNER TO kuser;

--
-- Name: jobs; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.jobs (
    id character varying(26) NOT NULL,
    type character varying(32),
    priority bigint,
    createat bigint,
    startat bigint,
    lastactivityat bigint,
    status character varying(32),
    progress bigint,
    data character varying(1024)
);


ALTER TABLE public.jobs OWNER TO kuser;

--
-- Name: licenses; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.licenses (
    id character varying(26) NOT NULL,
    createat bigint,
    bytes character varying(10000)
);


ALTER TABLE public.licenses OWNER TO kuser;

--
-- Name: oauthaccessdata; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.oauthaccessdata (
    clientid character varying(26),
    userid character varying(26),
    token character varying(26) NOT NULL,
    refreshtoken character varying(26),
    redirecturi character varying(256),
    expiresat bigint,
    scope character varying(128)
);


ALTER TABLE public.oauthaccessdata OWNER TO kuser;

--
-- Name: oauthapps; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.oauthapps (
    id character varying(26) NOT NULL,
    creatorid character varying(26),
    createat bigint,
    updateat bigint,
    clientsecret character varying(128),
    name character varying(64),
    description character varying(512),
    iconurl character varying(512),
    callbackurls character varying(1024),
    homepage character varying(256),
    istrusted boolean
);


ALTER TABLE public.oauthapps OWNER TO kuser;

--
-- Name: oauthauthdata; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.oauthauthdata (
    clientid character varying(26),
    userid character varying(26),
    code character varying(128) NOT NULL,
    expiresin integer,
    createat bigint,
    redirecturi character varying(256),
    state character varying(1024),
    scope character varying(128)
);


ALTER TABLE public.oauthauthdata OWNER TO kuser;

--
-- Name: outgoingwebhooks; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.outgoingwebhooks (
    id character varying(26) NOT NULL,
    token character varying(26),
    createat bigint,
    updateat bigint,
    deleteat bigint,
    creatorid character varying(26),
    classid character varying(26),
    branchid character varying(26),
    triggerwords character varying(1024),
    triggerwhen integer,
    callbackurls character varying(1024),
    displayname character varying(64),
    description character varying(128),
    contenttype character varying(128)
);


ALTER TABLE public.outgoingwebhooks OWNER TO kuser;

--
-- Name: pluginkeyvaluestore; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.pluginkeyvaluestore (
    pluginid character varying(190) NOT NULL,
    pkey character varying(50) NOT NULL,
    pvalue bytea
);


ALTER TABLE public.pluginkeyvaluestore OWNER TO kuser;

--
-- Name: posts; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.posts (
    id character varying(26) NOT NULL,
    createat bigint,
    updateat bigint,
    editat bigint,
    deleteat bigint,
    ispinned boolean,
    userid character varying(26),
    classid character varying(26),
    rootid character varying(26),
    parentid character varying(26),
    originalid character varying(26),
    message character varying(65535),
    type character varying(26),
    props character varying(8000),
    hashtags character varying(1000),
    filenames character varying(4000),
    fileids character varying(150),
    hasreactions boolean
);


ALTER TABLE public.posts OWNER TO kuser;

--
-- Name: preferences; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.preferences (
    userid character varying(26) NOT NULL,
    category character varying(32) NOT NULL,
    name character varying(32) NOT NULL,
    value character varying(2000)
);


ALTER TABLE public.preferences OWNER TO kuser;

--
-- Name: reactions; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.reactions (
    userid character varying(26) NOT NULL,
    postid character varying(26) NOT NULL,
    emojiname character varying(64) NOT NULL,
    createat bigint
);


ALTER TABLE public.reactions OWNER TO kuser;

--
-- Name: roles; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.roles (
    id character varying(26) NOT NULL,
    name character varying(64),
    displayname character varying(128),
    description character varying(1024),
    createat bigint,
    updateat bigint,
    deleteat bigint,
    permissions character varying(4096),
    schememanaged boolean,
    builtin boolean
);


ALTER TABLE public.roles OWNER TO kuser;

--
-- Name: schemes; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.schemes (
    id character varying(26) NOT NULL,
    name character varying(64),
    displayname character varying(128),
    description character varying(1024),
    createat bigint,
    updateat bigint,
    deleteat bigint,
    scope character varying(32),
    defaultbranchadminrole character varying(64),
    defaultbranchuserrole character varying(64),
    defaultclassadminrole character varying(64),
    defaultclassuserrole character varying(64)
);


ALTER TABLE public.schemes OWNER TO kuser;

--
-- Name: sessions; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.sessions (
    id character varying(26) NOT NULL,
    token character varying(26),
    createat bigint,
    expiresat bigint,
    lastactivityat bigint,
    userid character varying(26),
    deviceid character varying(512),
    roles character varying(64),
    isoauth boolean,
    props character varying(1000)
);


ALTER TABLE public.sessions OWNER TO kuser;

--
-- Name: status; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.status (
    userid character varying(26) NOT NULL,
    status character varying(32),
    manual boolean,
    lastactivityat bigint
);


ALTER TABLE public.status OWNER TO kuser;

--
-- Name: systems; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.systems (
    name character varying(64) NOT NULL,
    value character varying(1024)
);


ALTER TABLE public.systems OWNER TO kuser;

--
-- Name: branchmembers; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.branchmembers (
    branchid character varying(26) NOT NULL,
    userid character varying(26) NOT NULL,
    roles character varying(64),
    deleteat bigint,
    schemeuser boolean,
    schemeadmin boolean
);


ALTER TABLE public.branchmembers OWNER TO kuser;

--
-- Name: branches; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.branches (
    id character varying(26) NOT NULL,
    createat bigint,
    updateat bigint,
    deleteat bigint,
    displayname character varying(64),
    name character varying(64),
    description character varying(255),
    email character varying(128),
    type text,
    companyname character varying(64),
    alloweddomains character varying(500),
    inviteid character varying(32),
    allowopeninvite boolean,
    lastbranchiconupdate bigint,
    schemeid text
);


ALTER TABLE public.branches OWNER TO kuser;

--
-- Name: tokens; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.tokens (
    token character varying(64) NOT NULL,
    createat bigint,
    type character varying(64),
    extra character varying(128)
);


ALTER TABLE public.tokens OWNER TO kuser;

--
-- Name: useraccesstokens; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.useraccesstokens (
    id character varying(26) NOT NULL,
    token character varying(26),
    userid character varying(26),
    description character varying(512),
    isactive boolean
);


ALTER TABLE public.useraccesstokens OWNER TO kuser;

--
-- Name: users; Type: TABLE; Schema: public; Owner: kuser; Tablespace: 
--

CREATE TABLE public.users (
    id character varying(26) NOT NULL,
    createat bigint,
    updateat bigint,
    deleteat bigint,
    username character varying(64),
    password character varying(128),
    authdata character varying(128),
    authservice character varying(32),
    email character varying(128),
    emailverified boolean,
    nickname character varying(64),
    firstname character varying(64),
    lastname character varying(64),
    "position" character varying(128),
    roles character varying(256),
    allowmarketing boolean,
    props character varying(4000),
    notifyprops character varying(2000),
    lastpasswordupdate bigint,
    lastpictureupdate bigint,
    failedattempts integer,
    locale character varying(5),
    timezone character varying(256),
    mfaactive boolean,
    mfasecret character varying(128)
);


ALTER TABLE public.users OWNER TO kuser;

--
-- Data for Name: audits; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.audits (id, createat, userid, action, extrainfo, ipaddress, sessionid) FROM stdin;
\.


--
-- Data for Name: classmemberhistory; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.classmemberhistory (classid, userid, jointime, leavetime) FROM stdin;
\.


--
-- Data for Name: classmembers; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.classmembers (classid, userid, roles, lastviewedat, msgcount, mentioncount, notifyprops, lastupdateat, schemeuser, schemeadmin) FROM stdin;
\.


--
-- Data for Name: classes; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.classes (id, createat, updateat, deleteat, branchid, type, displayname, name, header, purpose, lastpostat, totalmsgcount, extraupdateat, creatorid, schemeid) FROM stdin;
\.


--
-- Data for Name: clusterdiscovery; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.clusterdiscovery (id, type, clustername, hostname, gossipport, port, createat, lastpingat) FROM stdin;
\.


--
-- Data for Name: commands; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.commands (id, token, createat, updateat, deleteat, creatorid, branchid, trigger, method, username, iconurl, autocomplete, autocompletedesc, autocompletehint, displayname, description, url) FROM stdin;
\.


--
-- Data for Name: commandwebhooks; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.commandwebhooks (id, createat, commandid, userid, classid, rootid, parentid, usecount) FROM stdin;
\.


--
-- Data for Name: compliances; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.compliances (id, createat, userid, status, count, "desc", type, startat, endat, keywords, emails) FROM stdin;
\.


--
-- Data for Name: emoji; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.emoji (id, createat, updateat, deleteat, creatorid, name) FROM stdin;
\.


--
-- Data for Name: fileinfo; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.fileinfo (id, creatorid, postid, createat, updateat, deleteat, path, thumbnailpath, previewpath, name, extension, size, mimetype, width, height, haspreviewimage) FROM stdin;
\.


--
-- Data for Name: incomingwebhooks; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.incomingwebhooks (id, createat, updateat, deleteat, userid, classid, branchid, displayname, description, username, iconurl, classlocked) FROM stdin;
\.


--
-- Data for Name: jobs; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.jobs (id, type, priority, createat, startat, lastactivityat, status, progress, data) FROM stdin;
\.


--
-- Data for Name: licenses; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.licenses (id, createat, bytes) FROM stdin;
\.


--
-- Data for Name: oauthaccessdata; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.oauthaccessdata (clientid, userid, token, refreshtoken, redirecturi, expiresat, scope) FROM stdin;
\.


--
-- Data for Name: oauthapps; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.oauthapps (id, creatorid, createat, updateat, clientsecret, name, description, iconurl, callbackurls, homepage, istrusted) FROM stdin;
\.


--
-- Data for Name: oauthauthdata; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.oauthauthdata (clientid, userid, code, expiresin, createat, redirecturi, state, scope) FROM stdin;
\.


--
-- Data for Name: outgoingwebhooks; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.outgoingwebhooks (id, token, createat, updateat, deleteat, creatorid, classid, branchid, triggerwords, triggerwhen, callbackurls, displayname, description, contenttype) FROM stdin;
\.


--
-- Data for Name: pluginkeyvaluestore; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.pluginkeyvaluestore (pluginid, pkey, pvalue) FROM stdin;
\.


--
-- Data for Name: posts; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.posts (id, createat, updateat, editat, deleteat, ispinned, userid, classid, rootid, parentid, originalid, message, type, props, hashtags, filenames, fileids, hasreactions) FROM stdin;
\.


--
-- Data for Name: preferences; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.preferences (userid, category, name, value) FROM stdin;
\.


--
-- Data for Name: reactions; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.reactions (userid, postid, emojiname, createat) FROM stdin;
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.roles (id, name, displayname, description, createat, updateat, deleteat, permissions, schememanaged, builtin) FROM stdin;
aap88jdt37dgdgkek1c7dq69ua	branch_post_all	authentication.roles.branch_post_all.name	authentication.roles.branch_post_all.description	1552912816230	1552912816230	0	 create_post	f	t
masesduwobn95dqoyba5xmtz5o	branch_post_all_public	authentication.roles.branch_post_all_public.name	authentication.roles.branch_post_all_public.description	1552912816258	1552912816258	0	 create_post_public	f	t
ufy3o8h1y3g4bgqeyw7yb6hrwe	system_post_all	authentication.roles.system_post_all.name	authentication.roles.system_post_all.description	1552912816269	1552912816269	0	 create_post	f	t
7ptq38iy4br59q8y4zt9mm3zwy	system_post_all_public	authentication.roles.system_post_all_public.name	authentication.roles.system_post_all_public.description	1552912816288	1552912816288	0	 create_post_public	f	t
wpxrpuiyo3bgdf34u7t65gcota	system_user_access_token	authentication.roles.system_user_access_token.name	authentication.roles.system_user_access_token.description	1552912816404	1552912816404	0	 create_user_access_token read_user_access_token revoke_user_access_token	f	t
fomn851ie3gmz8zwr87szazm6w	class_user	authentication.roles.class_user.name	authentication.roles.class_user.description	1552912816614	1552912816614	0	 read_class add_reaction remove_reaction manage_public_class_members upload_file get_public_link create_post use_slash_commands manage_private_class_members delete_post edit_post	t	t
xjxw3p6ect8bjfre7wc5jhwbqr	class_admin	authentication.roles.class_admin.name	authentication.roles.class_admin.description	1552912816669	1552912816669	0	 manage_class_roles	t	t
q5qjsjsn3py5mfodcirqjkhsjy	branch_user	authentication.roles.branch_user.name	authentication.roles.branch_user.description	1552912816680	1552912816680	0	 list_branch_classes join_public_classes read_public_class view_branch create_public_class manage_public_class_properties delete_public_class create_private_class manage_private_class_properties delete_private_class invite_user add_user_to_branch	t	t
ntqm5c1rbjb9mrh69zagibxoxa	branch_admin	authentication.roles.branch_admin.name	authentication.roles.branch_admin.description	1552912816746	1552912816746	0	 edit_others_posts remove_user_from_branch manage_branch import_branch manage_branch_roles manage_class_roles manage_others_webhooks manage_slash_commands manage_others_slash_commands manage_webhooks delete_post delete_others_posts	t	t
ts6aqp9p6jy97jwyf6wh4f5qaa	system_user	authentication.roles.global_user.name	authentication.roles.global_user.description	1552912816757	1552912816913	0	 create_direct_class create_group_class permanent_delete_user create_branch manage_emojis	t	t
twatrmjz8i8spfdyus18bm4nth	system_admin	authentication.roles.global_admin.name	authentication.roles.global_admin.description	1552912816481	1552912816923	0	 assign_system_admin_role manage_system manage_roles manage_public_class_properties manage_public_class_members manage_private_class_members delete_public_class create_public_class manage_private_class_properties delete_private_class create_private_class manage_system_wide_oauth manage_others_webhooks edit_other_users manage_oauth invite_user delete_post delete_others_posts create_branch add_user_to_branch list_users_without_branch manage_jobs create_post_public create_post_ephemeral create_user_access_token read_user_access_token revoke_user_access_token remove_others_reactions list_branch_classes join_public_classes read_public_class view_branch read_class add_reaction remove_reaction upload_file get_public_link create_post use_slash_commands edit_others_posts remove_user_from_branch manage_branch import_branch manage_branch_roles manage_class_roles manage_slash_commands manage_others_slash_commands manage_webhooks edit_post manage_emojis manage_others_emojis	t	t
\.


--
-- Data for Name: schemes; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.schemes (id, name, displayname, description, createat, updateat, deleteat, scope, defaultbranchadminrole, defaultbranchuserrole, defaultclassadminrole, defaultclassuserrole) FROM stdin;
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.sessions (id, token, createat, expiresat, lastactivityat, userid, deviceid, roles, isoauth, props) FROM stdin;
\.


--
-- Data for Name: status; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.status (userid, status, manual, lastactivityat) FROM stdin;
\.


--
-- Data for Name: systems; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.systems (name, value) FROM stdin;
Version	5.0.0
AsymmetricSigningKey	{"ecdsa_key":{"curve":"P-256","x":50494983991025284560870211683226455202411615657166048251398890171377825517363,"y":113694733845764674468191147267904180878076486503487433150108745296643202957034,"d":85042364128488616037616885822024419913274924562562115600648814391088417875310}}
AdvancedPermissionsMigrationComplete	true
EmojisPermissionsMigrationComplete	true
DiagnosticId	up3o75jkjbbs8dbawiwypzwrmc
LastSecurityTime	1552912819442
\.


--
-- Data for Name: branchmembers; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.branchmembers (branchid, userid, roles, deleteat, schemeuser, schemeadmin) FROM stdin;
\.


--
-- Data for Name: branches; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.branches (id, createat, updateat, deleteat, displayname, name, description, email, type, companyname, alloweddomains, inviteid, allowopeninvite, lastbranchiconupdate, schemeid) FROM stdin;
\.


--
-- Data for Name: tokens; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.tokens (token, createat, type, extra) FROM stdin;
\.


--
-- Data for Name: useraccesstokens; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.useraccesstokens (id, token, userid, description, isactive) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: kuser
--

COPY public.users (id, createat, updateat, deleteat, username, password, authdata, authservice, email, emailverified, nickname, firstname, lastname, "position", roles, allowmarketing, props, notifyprops, lastpasswordupdate, lastpictureupdate, failedattempts, locale, timezone, mfaactive, mfasecret) FROM stdin;
\.


--
-- Name: audits_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.audits
    ADD CONSTRAINT audits_pkey PRIMARY KEY (id);


--
-- Name: classmemberhistory_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.classmemberhistory
    ADD CONSTRAINT classmemberhistory_pkey PRIMARY KEY (classid, userid, jointime);


--
-- Name: classmembers_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.classmembers
    ADD CONSTRAINT classmembers_pkey PRIMARY KEY (classid, userid);


--
-- Name: classes_name_branchid_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.classes
    ADD CONSTRAINT classes_name_branchid_key UNIQUE (name, branchid);


--
-- Name: classes_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.classes
    ADD CONSTRAINT classes_pkey PRIMARY KEY (id);


--
-- Name: clusterdiscovery_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.clusterdiscovery
    ADD CONSTRAINT clusterdiscovery_pkey PRIMARY KEY (id);


--
-- Name: commands_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.commands
    ADD CONSTRAINT commands_pkey PRIMARY KEY (id);


--
-- Name: commandwebhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.commandwebhooks
    ADD CONSTRAINT commandwebhooks_pkey PRIMARY KEY (id);


--
-- Name: compliances_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.compliances
    ADD CONSTRAINT compliances_pkey PRIMARY KEY (id);


--
-- Name: emoji_name_deleteat_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.emoji
    ADD CONSTRAINT emoji_name_deleteat_key UNIQUE (name, deleteat);


--
-- Name: emoji_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.emoji
    ADD CONSTRAINT emoji_pkey PRIMARY KEY (id);


--
-- Name: fileinfo_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.fileinfo
    ADD CONSTRAINT fileinfo_pkey PRIMARY KEY (id);


--
-- Name: incomingwebhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.incomingwebhooks
    ADD CONSTRAINT incomingwebhooks_pkey PRIMARY KEY (id);


--
-- Name: jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (id);


--
-- Name: licenses_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_pkey PRIMARY KEY (id);


--
-- Name: oauthaccessdata_clientid_userid_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.oauthaccessdata
    ADD CONSTRAINT oauthaccessdata_clientid_userid_key UNIQUE (clientid, userid);


--
-- Name: oauthaccessdata_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.oauthaccessdata
    ADD CONSTRAINT oauthaccessdata_pkey PRIMARY KEY (token);


--
-- Name: oauthapps_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.oauthapps
    ADD CONSTRAINT oauthapps_pkey PRIMARY KEY (id);


--
-- Name: oauthauthdata_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.oauthauthdata
    ADD CONSTRAINT oauthauthdata_pkey PRIMARY KEY (code);


--
-- Name: outgoingwebhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.outgoingwebhooks
    ADD CONSTRAINT outgoingwebhooks_pkey PRIMARY KEY (id);


--
-- Name: pluginkeyvaluestore_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.pluginkeyvaluestore
    ADD CONSTRAINT pluginkeyvaluestore_pkey PRIMARY KEY (pluginid, pkey);


--
-- Name: posts_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.posts
    ADD CONSTRAINT posts_pkey PRIMARY KEY (id);


--
-- Name: preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.preferences
    ADD CONSTRAINT preferences_pkey PRIMARY KEY (userid, category, name);


--
-- Name: reactions_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_pkey PRIMARY KEY (postid, userid, emojiname);


--
-- Name: roles_name_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);


--
-- Name: roles_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: schemes_name_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.schemes
    ADD CONSTRAINT schemes_name_key UNIQUE (name);


--
-- Name: schemes_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.schemes
    ADD CONSTRAINT schemes_pkey PRIMARY KEY (id);


--
-- Name: sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: status_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.status
    ADD CONSTRAINT status_pkey PRIMARY KEY (userid);


--
-- Name: systems_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_pkey PRIMARY KEY (name);


--
-- Name: branchmembers_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.branchmembers
    ADD CONSTRAINT branchmembers_pkey PRIMARY KEY (branchid, userid);


--
-- Name: branches_name_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.branches
    ADD CONSTRAINT branches_name_key UNIQUE (name);


--
-- Name: branches_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.branches
    ADD CONSTRAINT branches_pkey PRIMARY KEY (id);


--
-- Name: tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.tokens
    ADD CONSTRAINT tokens_pkey PRIMARY KEY (token);


--
-- Name: useraccesstokens_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.useraccesstokens
    ADD CONSTRAINT useraccesstokens_pkey PRIMARY KEY (id);


--
-- Name: useraccesstokens_token_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.useraccesstokens
    ADD CONSTRAINT useraccesstokens_token_key UNIQUE (token);


--
-- Name: users_authdata_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_authdata_key UNIQUE (authdata);


--
-- Name: users_email_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users_pkey; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users_username_key; Type: CONSTRAINT; Schema: public; Owner: kuser; Tablespace: 
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: idx_audits_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_audits_user_id ON public.audits USING btree (userid);


--
-- Name: idx_classmembers_class_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classmembers_class_id ON public.classmembers USING btree (classid);


--
-- Name: idx_classmembers_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classmembers_user_id ON public.classmembers USING btree (userid);


--
-- Name: idx_classes_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classes_create_at ON public.classes USING btree (createat);


--
-- Name: idx_classes_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classes_delete_at ON public.classes USING btree (deleteat);


--
-- Name: idx_classes_displayname_lower; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classes_displayname_lower ON public.classes USING btree (lower((displayname)::text));


--
-- Name: idx_classes_name; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classes_name ON public.classes USING btree (name);


--
-- Name: idx_classes_name_lower; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classes_name_lower ON public.classes USING btree (lower((name)::text));


--
-- Name: idx_classes_branch_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classes_branch_id ON public.classes USING btree (branchid);


--
-- Name: idx_classes_txt; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classes_txt ON public.classes USING gin (to_tsvector('english'::regconfig, (((name)::text || ' '::text) || (displayname)::text)));


--
-- Name: idx_classes_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_classes_update_at ON public.classes USING btree (updateat);


--
-- Name: idx_command_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_command_create_at ON public.commands USING btree (createat);


--
-- Name: idx_command_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_command_delete_at ON public.commands USING btree (deleteat);


--
-- Name: idx_command_branch_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_command_branch_id ON public.commands USING btree (branchid);


--
-- Name: idx_command_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_command_update_at ON public.commands USING btree (updateat);


--
-- Name: idx_command_webhook_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_command_webhook_create_at ON public.commandwebhooks USING btree (createat);


--
-- Name: idx_emoji_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_emoji_create_at ON public.emoji USING btree (createat);


--
-- Name: idx_emoji_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_emoji_delete_at ON public.emoji USING btree (deleteat);


--
-- Name: idx_emoji_name; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_emoji_name ON public.emoji USING btree (name);


--
-- Name: idx_emoji_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_emoji_update_at ON public.emoji USING btree (updateat);


--
-- Name: idx_fileinfo_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_fileinfo_create_at ON public.fileinfo USING btree (createat);


--
-- Name: idx_fileinfo_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_fileinfo_delete_at ON public.fileinfo USING btree (deleteat);


--
-- Name: idx_fileinfo_postid_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_fileinfo_postid_at ON public.fileinfo USING btree (postid);


--
-- Name: idx_fileinfo_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_fileinfo_update_at ON public.fileinfo USING btree (updateat);


--
-- Name: idx_incoming_webhook_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_incoming_webhook_create_at ON public.incomingwebhooks USING btree (createat);


--
-- Name: idx_incoming_webhook_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_incoming_webhook_delete_at ON public.incomingwebhooks USING btree (deleteat);


--
-- Name: idx_incoming_webhook_branch_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_incoming_webhook_branch_id ON public.incomingwebhooks USING btree (branchid);


--
-- Name: idx_incoming_webhook_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_incoming_webhook_update_at ON public.incomingwebhooks USING btree (updateat);


--
-- Name: idx_incoming_webhook_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_incoming_webhook_user_id ON public.incomingwebhooks USING btree (userid);


--
-- Name: idx_jobs_type; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_jobs_type ON public.jobs USING btree (type);


--
-- Name: idx_oauthaccessdata_client_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_oauthaccessdata_client_id ON public.oauthaccessdata USING btree (clientid);


--
-- Name: idx_oauthaccessdata_refresh_token; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_oauthaccessdata_refresh_token ON public.oauthaccessdata USING btree (refreshtoken);


--
-- Name: idx_oauthaccessdata_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_oauthaccessdata_user_id ON public.oauthaccessdata USING btree (userid);


--
-- Name: idx_oauthapps_creator_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_oauthapps_creator_id ON public.oauthapps USING btree (creatorid);


--
-- Name: idx_oauthauthdata_client_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_oauthauthdata_client_id ON public.oauthauthdata USING btree (code);


--
-- Name: idx_outgoing_webhook_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_outgoing_webhook_create_at ON public.outgoingwebhooks USING btree (createat);


--
-- Name: idx_outgoing_webhook_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_outgoing_webhook_delete_at ON public.outgoingwebhooks USING btree (deleteat);


--
-- Name: idx_outgoing_webhook_branch_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_outgoing_webhook_branch_id ON public.outgoingwebhooks USING btree (branchid);


--
-- Name: idx_outgoing_webhook_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_outgoing_webhook_update_at ON public.outgoingwebhooks USING btree (updateat);


--
-- Name: idx_posts_class_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_class_id ON public.posts USING btree (classid);


--
-- Name: idx_posts_class_id_delete_at_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_class_id_delete_at_create_at ON public.posts USING btree (classid, deleteat, createat);


--
-- Name: idx_posts_class_id_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_class_id_update_at ON public.posts USING btree (classid, updateat);


--
-- Name: idx_posts_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_create_at ON public.posts USING btree (createat);


--
-- Name: idx_posts_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_delete_at ON public.posts USING btree (deleteat);


--
-- Name: idx_posts_hashtags_txt; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_hashtags_txt ON public.posts USING gin (to_tsvector('english'::regconfig, (hashtags)::text));


--
-- Name: idx_posts_is_pinned; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_is_pinned ON public.posts USING btree (ispinned);


--
-- Name: idx_posts_message_txt; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_message_txt ON public.posts USING gin (to_tsvector('english'::regconfig, (message)::text));


--
-- Name: idx_posts_root_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_root_id ON public.posts USING btree (rootid);


--
-- Name: idx_posts_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_update_at ON public.posts USING btree (updateat);


--
-- Name: idx_posts_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_posts_user_id ON public.posts USING btree (userid);


--
-- Name: idx_preferences_category; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_preferences_category ON public.preferences USING btree (category);


--
-- Name: idx_preferences_name; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_preferences_name ON public.preferences USING btree (name);


--
-- Name: idx_preferences_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_preferences_user_id ON public.preferences USING btree (userid);


--
-- Name: idx_sessions_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_sessions_create_at ON public.sessions USING btree (createat);


--
-- Name: idx_sessions_expires_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_sessions_expires_at ON public.sessions USING btree (expiresat);


--
-- Name: idx_sessions_last_activity_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_sessions_last_activity_at ON public.sessions USING btree (lastactivityat);


--
-- Name: idx_sessions_token; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_sessions_token ON public.sessions USING btree (token);


--
-- Name: idx_sessions_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_sessions_user_id ON public.sessions USING btree (userid);


--
-- Name: idx_status_status; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_status_status ON public.status USING btree (status);


--
-- Name: idx_status_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_status_user_id ON public.status USING btree (userid);


--
-- Name: idx_branchmembers_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_branchmembers_delete_at ON public.branchmembers USING btree (deleteat);


--
-- Name: idx_branchmembers_branch_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_branchmembers_branch_id ON public.branchmembers USING btree (branchid);


--
-- Name: idx_branchmembers_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_branchmembers_user_id ON public.branchmembers USING btree (userid);


--
-- Name: idx_branches_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_branches_create_at ON public.branches USING btree (createat);


--
-- Name: idx_branches_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_branches_delete_at ON public.branches USING btree (deleteat);


--
-- Name: idx_branches_invite_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_branches_invite_id ON public.branches USING btree (inviteid);


--
-- Name: idx_branches_name; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_branches_name ON public.branches USING btree (name);


--
-- Name: idx_branches_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_branches_update_at ON public.branches USING btree (updateat);


--
-- Name: idx_user_access_tokens_token; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_user_access_tokens_token ON public.useraccesstokens USING btree (token);


--
-- Name: idx_user_access_tokens_user_id; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_user_access_tokens_user_id ON public.useraccesstokens USING btree (userid);


--
-- Name: idx_users_all_no_full_name_txt; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_all_no_full_name_txt ON public.users USING gin (to_tsvector('english'::regconfig, (((((username)::text || ' '::text) || (nickname)::text) || ' '::text) || (email)::text)));


--
-- Name: idx_users_all_txt; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_all_txt ON public.users USING gin (to_tsvector('english'::regconfig, (((((((((username)::text || ' '::text) || (firstname)::text) || ' '::text) || (lastname)::text) || ' '::text) || (nickname)::text) || ' '::text) || (email)::text)));


--
-- Name: idx_users_create_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_create_at ON public.users USING btree (createat);


--
-- Name: idx_users_delete_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_delete_at ON public.users USING btree (deleteat);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: idx_users_email_lower; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_email_lower ON public.users USING btree (lower((email)::text));


--
-- Name: idx_users_firstname_lower; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_firstname_lower ON public.users USING btree (lower((firstname)::text));


--
-- Name: idx_users_lastname_lower; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_lastname_lower ON public.users USING btree (lower((lastname)::text));


--
-- Name: idx_users_names_no_full_name_txt; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_names_no_full_name_txt ON public.users USING gin (to_tsvector('english'::regconfig, (((username)::text || ' '::text) || (nickname)::text)));


--
-- Name: idx_users_names_txt; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_names_txt ON public.users USING gin (to_tsvector('english'::regconfig, (((((((username)::text || ' '::text) || (firstname)::text) || ' '::text) || (lastname)::text) || ' '::text) || (nickname)::text)));


--
-- Name: idx_users_nickname_lower; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_nickname_lower ON public.users USING btree (lower((nickname)::text));


--
-- Name: idx_users_update_at; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_update_at ON public.users USING btree (updateat);


--
-- Name: idx_users_username_lower; Type: INDEX; Schema: public; Owner: kuser; Tablespace: 
--

CREATE INDEX idx_users_username_lower ON public.users USING btree (lower((username)::text));


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: kuser
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM kuser;
GRANT ALL ON SCHEMA public TO kuser;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

