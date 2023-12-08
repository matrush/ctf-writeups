import numpy as np
from PIL import Image
r = np.genfromtxt("data.txt", invalid_raise=False)
pixels = 255 * (1.0 - r.reshape((256, 256)))
im = Image.fromarray(pixels.astype(np.uint8), mode='L')
im.show()
im.save('flag.png')

# ptm{RRRRReversing_s0m3_bytecode_345674637}
