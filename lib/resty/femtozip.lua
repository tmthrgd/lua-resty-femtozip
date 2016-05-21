local ffi = require "ffi"
local base = require "resty.core.base"

local C = ffi.C
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_cast = ffi.cast
local setmetatable = setmetatable
local tonumber = tonumber
local type = type
local get_size_ptr = base.get_size_ptr
local get_string_buf = base.get_string_buf

ffi.cdef[[
typedef int (*fz_dest_writer)(const char *buf, size_t len, void *arg);

void *fz_load_model(const char *path);

void fz_release_model(void *model);

int fz_compress_writer(void *model, const char *source, size_t source_len,
	fz_dest_writer dest_writer, void *arg);

int fz_decompress_writer(void *model, const char *source, size_t source_len,
	fz_dest_writer dest_writer, void *arg);
]]

local _M = {}
local mt = { __index = _M }

function _M.load_model(path)
	local model = C.fz_load_model(path)
	if model == nil then
		return nil, "fz_load_model failed"
	end

	ffi_gc(model, C.fz_release_model)

	return setmetatable({ model = model }, mt)
end

function _M.compress(self, src)
	local model = assert(self.model, "not initialized")

	local dst
	local writer = ffi_cast("fz_dest_writer", function(buf, len, arg)
		dst = ffi_str(buf, len)
		return 0
	end)

	local rc = C.fz_compress_writer(model, src, #src, writer, nil)
	writer:free()

	if rc ~= 0 then
		return nil, "fz_compress_writer failed"
	end

	return dst
end

function _M.decompress(self, src)
	local model = assert(self.model, "not initialized")

	local dst
	local writer = ffi_cast("fz_dest_writer", function(buf, len, arg)
		dst = ffi_str(buf, len)
		return 0
	end)

	local rc = C.fz_decompress_writer(model, src, #src, writer, nil)
	writer:free()

	if rc ~= 0 then
		return nil, "fz_decompress_writer failed"
	end

	return dst
end

--local model = assert(femtozip.load_model("abc.model"))
--assert(model:decompress(assert(model:compress("abc")))) == "abc"

return _M
