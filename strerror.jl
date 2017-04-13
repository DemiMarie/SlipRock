function get_strerror(x, y)
  let buf = zeros(Int64, 10)
     try
     ccall((:c, "__xpg_strerror_r"), CInt, (
