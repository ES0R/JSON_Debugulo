# -*- coding: utf-8 -*-
"""
This function converts depth data to world coordinates

Author: GBC09 / BU05 / SW
SICK AG, Waldkirch
email: techsupport0905@sick.de

Copyright note: Redistribution and use in source, with or without modification, are permitted.

Liability clause: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import math
import numpy as np

plyHeader = """ply
format ascii 1.0
comment Exported by visionary python samples
element vertex {}
property float32 x
property float32 y
property float32 z
property uint8 r
property uint8 g
property uint8 b
property float32 i
end_header
"""

def convertToPointCloud(distData, intsData, cnfiData, myCamParams, isStereo):
    """
    Return values:
    wCoordinates: Nested List with the linewise data for a pointcloud file. Each list item is a list with the following entries 
                  X Y Z R G B I   i.e. point coordinates (XYZ), color (RGB) and intensity (I)
    distData: input distData reshaped to array with camera resolution
    """
    wCoordinates = []

    m_c2w = np.array(myCamParams.cam2worldMatrix)
    shape = (4, 4)
    m_c2w.shape = shape


    cnfiData = np.asarray(cnfiData).reshape(myCamParams.height,myCamParams.width)
    intsData = np.asarray(intsData).reshape(myCamParams.height,myCamParams.width)
    distData = np.asarray(list(distData)).reshape(myCamParams.height,myCamParams.width)

    if isStereo:

        #RGBA intensities
        intsData = np.asarray(intsData).astype('uint32').view('uint8').reshape(myCamParams.height,myCamParams.width, 4)
        intsData = np.frombuffer(intsData, np.uint8).reshape(myCamParams.height,myCamParams.width,4)
        color_map = intsData

        # Apply the Statemap to the Z-map
        zmapData_with_statemap = np.array(distData).reshape(myCamParams.height,myCamParams.width)

        for row in range(myCamParams.height):
            for col in range(myCamParams.width):
                if (cnfiData[row][col] != 0):
                    zmapData_with_statemap[row][col] = 0 # Set invalid pixels to lowest value
                else:
                    # use all "good" points to export to PLY

                    # transform into camera coordinates (zc, xc, yc)
                    xp = (myCamParams.cx - col) / myCamParams.fx
                    yp = (myCamParams.cy - row) / myCamParams.fy

                    # coordinate system local to the imager
                    zc = distData[row][col]
                    xc = xp * zc
                    yc = yp * zc

                    # convert to world coordinate system
                    xw = (m_c2w[0, 3] + zc * m_c2w[0, 2]  + yc * m_c2w[0, 1] + xc * m_c2w[0, 0])
                    yw = (m_c2w[1, 3] + zc * m_c2w[1, 2]  + yc * m_c2w[1, 1] + xc * m_c2w[1, 0])
                    zw = (m_c2w[2, 3] + zc * m_c2w[2, 2]  + yc * m_c2w[2, 1] + xc * m_c2w[2, 0])

                    # merge 3D coordinates and color
                    wCoordinates.append([xw, yw, zw, color_map[row][col][0], color_map[row][col][1], color_map[row][col][2], 0])

        return wCoordinates,distData

    else:

        for row in range(0, myCamParams.height):
            for col in range(0, myCamParams.width):

                #calculate radial distortion
                xp = (myCamParams.cx - col) / myCamParams.fx
                yp = (myCamParams.cy - row) / myCamParams.fy

                r2 = (xp * xp + yp * yp)
                r4 = r2 * r2

                k = 1 + myCamParams.k1 * r2 + myCamParams.k2 * r4

                xd = xp * k
                yd = yp * k

                d = distData[row][col]
                s0 = np.sqrt(xd*xd + yd*yd + 1)

                xc = xd * d / s0
                yc = yd * d / s0
                zc = d / s0 - myCamParams.f2rc

                # convert to world coordinate system
                xw = (m_c2w[0, 3] + zc * m_c2w[0, 2]  + yc * m_c2w[0, 1] + xc * m_c2w[0, 0])
                yw = (m_c2w[1, 3] + zc * m_c2w[1, 2]  + yc * m_c2w[1, 1] + xc * m_c2w[1, 0])
                zw = (m_c2w[2, 3] + zc * m_c2w[2, 2]  + yc * m_c2w[2, 1] + xc * m_c2w[2, 0])

                # convert to full decibel values * 0.01, which is the same format that Sopas uses for point cloud export
                intsSopasFormat = round(0.2 * math.log10(intsData[row][col]), 2) if intsData[row][col] > 0 else 0

                # merge 3D coordinates and intensity
                wCoordinates.append([xw, yw, zw, 0, 0, 0, intsSopasFormat])

        return wCoordinates, distData

def writePointCloudToFile(filename, wCoordinates):
    with open(filename, 'w') as f:
        f.write(plyHeader.format(len(wCoordinates)))
        for item in wCoordinates:
            for l in item:
                f.write(("{} ").format(l))
            f.write("\n")
