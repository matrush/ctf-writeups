load("something")

X = ((mtov / 3 - 69) * 5 + 42)
rot = t(t(X)[1:50,])
x = t(t(X)[51:100,])
# https://stackoverflow.com/a/29784476
data = t(t(x %*% t(rot)) + 0.7)
write.table(data, file="data.txt", row.names=FALSE, col.names=FALSE)
