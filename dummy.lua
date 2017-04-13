local memo = {}
function fn(expr)
   if memo[expr] == nil then
      local code = ('return function (a,b,c,d,e) %s end'):format(expr)
      memo[expr] = assert(loadstring(code))()
   end
   return memo[expr]
end

local acc = 0
for i = 1, 100 do
   acc = acc + fn[[return a*b]](21, 2)
end
assert(acc == 42 * 100)
