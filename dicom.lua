B = require 'buffer'

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

-- static identifiers
DICOM_USER_INFO = 0x50
DICOM_USER_IDENTITY = 0x58
ASSOCIATE_REQUEST = string.fromhex("0100")
ASSOCIATE_ACCEPT = string.fromhex("0200")
ASSOCIATE_REJECT = string.fromhex("0300")
EMPTY_PDU_LENGTH = string.fromhex("00000000")
PROTOCOL_VERSION = string.fromhex("0001")
RESERVED_FIELDS_4 = string.fromhex("0000")
EMPTY_AE = string.fromhex("20202020202020202020202020202020")
LONG_PADDING = string.fromhex("0000000000000000000000000000000000000000000000000000000000000000")

-- initializes the rejection template
function setup_a_associate_rj_tmpl()
local tmpl = B''
tmpl:insert (string.fromhex("0300")) -- associate rejection
tmpl:insert (string.fromhex("00000004")) -- PDU length. always 4 in this case.
tmpl:insert (string.fromhex("00000000")) -- 4 bytes of reject, to be overwritten by real rejection code
a_associate_rj_tmpl = tmpl
end

function send_a_associate_rj_121(applet)
local tmpl = B(a_associate_rj_tmpl)
tmpl:set(7,string.fromhex("00010201"))
applet:send(tostring(tmpl))
end

function send_a_associate_rj_113(applet)
local tmpl = B(a_associate_rj_tmpl)
tmpl:set(7,string.fromhex("00010103"))
applet:send(tostring(tmpl))
end

function send_a_associate_rj_117(applet)
local tmpl = B(a_associate_rj_tmpl)
tmpl:set(7,string.fromhex("00010107"))
applet:send(tostring(tmpl))
end

function send_a_associate_rj_231(applet)
local tmpl = B(a_associate_rj_tmpl)
tmpl:set(7,string.fromhex("00020301"))
applet:send(tostring(tmpl))
end

function send_a_associate_rj_232(applet)
local tmpl = B(a_associate_rj_tmpl)
tmpl:set(7,string.fromhex("00020302"))
applet:send(tostring(tmpl))
end

function dicom_process_transaction(txn)
-- check if we already processed this transaction
if txn:get_priv() and txn:get_priv()["dicom.processed"] then
return -- we already processed and populated the private cache
end -- dicom already processed
local t = {}
bytes_received = tonumber(txn.sf:req_len())
if bytes_received < 42 then -- won't parse these requests. these may result in bogus identification
core.log(core.info,"request too short: " .. tostring(txn.sf:req_len()))
return false
end -- request too short
local offset = 74 -- offset to first dicom item after padding
t["dicom.called"] = txn.sf:payload(10,16)
t["dicom.calling"] = txn.sf:payload(26,16)
while offset < bytes_received do 
local item_type = string.byte(txn.sf:payload(offset,1))
local item_length = string.byte(txn.sf:payload(offset+2,1)) * 16 + string.byte(txn.sf:payload(offset+3,1))
if item_type == DICOM_USER_INFO then
local sub_offset = offset + 4
while sub_offset < offset + item_length do
local sub_item_type = string.byte(txn.sf:payload(sub_offset,1))
local sub_item_length = string.byte(txn.sf:payload(sub_offset+2,1)) * 16 + string.byte(txn.sf:payload(sub_offset+3,1))
if sub_item_type == DICOM_USER_IDENTITY then
t["dicom.user_identity_type"] = string.byte(txn.sf:payload(sub_offset+4,1))
local user_identity_pri_length = string.byte(txn.sf:payload(sub_offset+6,1)) * 16 + string.byte(txn.sf:payload(sub_offset+6+1,1))
t["dicom.user_identity_pri_value"] = txn.sf:payload(sub_offset+8,user_identity_pri_length)
local user_identity_sec_length = string.byte(txn.sf:payload(sub_offset+8+user_identity_pri_length,1)) * 16 + string.byte(txn.sf:payload(sub_offset+8+user_identity_pri_length+1,1))
t["dicom.user_identity_sec_value"] = txn.sf:payload(sub_offset+8+user_identity_pri_length+2,user_identity_sec_length)
end -- matched user identity association subitem
sub_offset = sub_offset + 4 + sub_item_length
end -- iterate over user info subitems
end -- matched user info association item
offset = offset + item_length + 4 -- 4 for item_length field then actual item length
end -- while
t["dicom.processed"] = true
txn:set_priv(t)
end -- function

function dicom_auth(txn)
dicom_process_transaction(txn)
-- replace with your own logic / call another function using the transaction variables
-- core.log(core.info, "called: " .. t["dicom.called"] .. " calling: " .. t["dicom.calling"]) -- .. " ident_pri: " .. t["dicom.user_identity_pri_value"])
return false
end

function dicom_get_calling_ae(txn)
dicom_process_transaction(txn)
local t = txn:get_priv()
return t["dicom.calling"]
end

function dicom_get_called_ae(txn)
dicom_process_transaction(txn)
local t = txn:get_priv()
return t["dicom.called"]
end

function dicom_get_user_identity_type(txn)
dicom_process_transaction(txn)
local t = txn:get_priv()
return t["dicom.user_identity_type"]
end

function dicom_get_user_identity_pri_value(txn)
dicom_process_transaction(txn)
local t = txn:get_priv()
return t["dicom.user_identity_pri_value"]
end

function dicom_get_user_identity_sec_value(txn)
dicom_process_transaction(txn)
local t = txn:get_priv()
return t["dicom.user_identity_sec_value"]
end

-- function my_sample_auth_function(src,called,calling,certdn,user_identity_type,user_identity_pri,user_identity_sec)
-- authenticate an ip/called/calling triplet
-- if src == "127.0.0.1" and called == "AUTHDSERVER     " and calling == "AUTHDCLIENT     " then
-- core.log(core.info,"authenticated by AE title name and IP")
-- return true
-- end
-- authenticate by certificate and called AE:
-- if certdn == "/C=US/ST=California/L=Viz.ai/O=Viz.ai/OU=MyUnit/CN=MyCTMachine/emailAddress=gil@viz.ai" and called == "AUTHDSERVER  " then
-- core.log(core.info,"authenticated by AE title and certificate")
-- return true
-- end
-- authenticate by username/password user identity:
-- if user_identity_pri == "test_username" and user_identity_sec == "test_password" then
-- core.log(core.info,"authenticated by username/password")
-- return true
-- end

-- create the global template
setup_a_associate_rj_tmpl()

-- dicom auth function
core.register_fetches("dicom_auth",dicom_auth)
core.register_fetches("dicom_calling_ae",dicom_get_calling_ae)
core.register_fetches("dicom_called_ae",dicom_get_called_ae)
core.register_fetches("dicom_user_identity_type",dicom_get_user_identity_type)
core.register_fetches("dicom_user_identity_pri_value",dicom_get_user_identity_pri_value)
core.register_fetches("dicom_user_identity_sec_value",dicom_get_user_identity_sec_value)

-- dicom rejector virtual backends
core.register_service("dicom_snubby_121", "tcp", send_a_associate_rj_121)
core.register_service("dicom_snubby_113", "tcp", send_a_associate_rj_113)
core.register_service("dicom_snubby_117", "tcp", send_a_associate_rj_117)
core.register_service("dicom_snubby_231", "tcp", send_a_associate_rj_231)
core.register_service("dicom_snubby_232", "tcp", send_a_associate_rj_232)
