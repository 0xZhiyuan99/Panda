from skimage import io
import os

def corp_margin(img):
        img2=img.sum(axis=2)
        (row,col)=img2.shape
        row_top=0
        raw_down=0
        col_top=0
        col_down=0

        tmp = img2.sum(axis=1)[0]
        for r in range(0,row):
                if img2.sum(axis=1)[r] != tmp:
                        row_top=r
                        break
 
        tmp = img2.sum(axis=1)[row-1]
        for r in range(row-1,0,-1):
                if img2.sum(axis=1)[r] != tmp:
                        raw_down=r
                        break
 
        tmp = img2.sum(axis=0)[0]
        for c in range(0,col):
                if img2.sum(axis=0)[c] != tmp:
                        col_top=c
                        break
        
        tmp = img2.sum(axis=0)[col-1]
        for c in range(col-1,0,-1):
                if img2.sum(axis=0)[c] != tmp:
                        col_down=c
                        break
 
        new_img=img[row_top-1:raw_down+2,col_top-1:col_down+2,0:3]
        print(row,col)
        print(row_top-1,raw_down+2,col_top-1,col_down+2)
        return new_img

for filename in os.listdir("/home/daige/Desktop/123/"):
    if not os.path.isfile('/home/daige/Desktop/123/' + filename):
        continue
    print(filename)
    im = io.imread('/home/daige/Desktop/123/' + filename)
    img_re = corp_margin(im)
    io.imsave('/home/daige/Desktop/123/results/' + filename, img_re)
    io.imshow(img_re)