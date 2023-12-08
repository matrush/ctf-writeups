# TongueTwister

## Challenge [[Link]](https://ctftime.org/event/2033)
> Rory's rugged rangers rode rapidly around rugged rocky ridges, racing restless river rapids, resisting rough, roaring rains.
>
> Author: @matpro

## Solution
From the description and the given file we know it's about R language. First we decode the encoded R code and get this:
```R
load('something_else')
function() {
  library('png')
  library('colorspace')

  image_path <- "./flag.png"
  n <- 50

  x <- readPNG(image_path)

  y <- rgb(x[,,1], x[,,2], x[,,3])
  yg <- desaturate(y)
  yn <- col2rgb(yg)[1, ]/255
  dim(y) <- dim(yg) <- dim(yn) <- dim(x)[1:2]

  V <- prcomp(yn)

  X <- t(rbind(t(V$rotation[,1:n]), t(V$x[,1:n])))
  X <- X - 42
  X <- X / 5
  X <- X + 69
  X <- X * 3

  load("something")

  if (max(abs(X - mtov)) < 6e-5) {
    cat("Yes!")
  } else {
    cat("Try harder")
    cat(max(abs(X - mtov)))
  }
}
```

We can see it's trying to compare a processed matrix `X` from an image with the known `mtov`. The function `prcomp` is Principal Components Analysis. After some research we found [this](https://stackoverflow.com/q/29783790) to help us reverse PCA in `prcomp` to get original data. However one challenge is that in the original code, only the `r` channel of the `rgb` channels are preserved throughout the processing, so we have to treat the `rgb` image as a greyscale image now as color shouldn't affect how the flag looks like too much.

From the link in the above, it mentioned that `prcomp` will center the variables so we need to add the subtracted means back.
```R
t(t(pca$x %*% t(pca$rotation)) + pca$center)
```
However we don't have the `pca$center` in our data, thus we have to manually add some value back to make sure the data is between `0.0 ~ 1.0`. In our experiment, `0.7` seems to be a good choice.

```R
X = ((mtov / 3 - 69) * 5 + 42)
rot = t(t(X)[1:50,])
x = t(t(X)[51:100,])
# https://stackoverflow.com/a/29784476
data = t(t(x %*% t(rot)) + 0.7)
write.table(data, file="data.txt", row.names=FALSE, col.names=FALSE)
```

Running this in R can give us the `yn` data. Then we use `PIL` in python to draw it out as a greyscale image. In the final image we get the blurry but readable flag. We can also keep tweaking the `0.7` to get the rest of the flag if it's not clear enough.

## Flag
`ptm{RRRRReversing_s0m3_bytecode_345674637} `
