from pygame import display as pygdisplay
from pygame import draw as pygdraw
from pygame import font as pygfont
from pygame import image as pygimage
from pygame import init as pyginit
from pygame import quit as pygquit
from pygame import Rect as pygRect

import copy


def interpolate_tuple(startcolor, goalcolor, steps):
    """
    Take two RGB color sets and mix them over a specified number of steps.
    Return the list
    """
    R = startcolor[0]
    G = startcolor[1]
    B = startcolor[2]

    targetR = goalcolor[0]
    targetG = goalcolor[1]
    targetB = goalcolor[2]

    DiffR = targetR - R
    DiffG = targetG - G
    DiffB = targetB - B

    gradient = []

    for i in range(0, steps + 1):
        iR = R + (DiffR * i / steps)
        iG = G + (DiffG * i / steps)
        iB = B + (DiffB * i / steps)

        color = (iR,iG,iB)
        gradient.append(color)

    return gradient

def draw(grid, grid_type, ROWS=256, COLUMNS=256, GRID_LINE=16):
    BLACK = (0, 0, 0)
    WHITE = (255, 255, 255)
    GREEN = (0, 255, 0)
    RED = (255, 0, 0)
    BLUE = (0, 0, 255)

    WIDTH = 9
    HEIGHT = 9
    MARGIN = 1
    W_HEIGHT = (ROWS*10)+1
    W_WIDTH = (COLUMNS*10)+1
    WINDOW_SIZE = [W_HEIGHT, W_WIDTH]

    subgrid = []
    for row in range(ROWS/GRID_LINE):
        subgrid.append([])
        for column in range(COLUMNS/GRID_LINE):
            subgrid[row].append(0)

    pygfont.init()

    myfont = pygfont.SysFont('Times New Roman', 9)
    download=myfont.render('D', True, WHITE)
    upload=myfont.render('U', True, WHITE)
    bidirectional=myfont.render('B', True, WHITE)
    screen = pygdisplay.set_mode(WINDOW_SIZE)
    pygdisplay.set_caption(grid_type + " Plot")
    screen.fill(WHITE)

    # check which grids should be drawn
    new_grid = copy.deepcopy(grid)
    if grid_type.startswith('ASN-') or grid_type.startswith('Private_RFC_1918-'):
        for r in range(ROWS/GRID_LINE):
            for c in range(COLUMNS/GRID_LINE):
                box_in = 0
                box_out = 0
                for row in range(ROWS/GRID_LINE):
                    for column in range(COLUMNS/GRID_LINE):
                        y = (r*(ROWS/GRID_LINE))+row
                        x = (c*(COLUMNS/GRID_LINE))+column
                        box_in += new_grid[y][x][0]
                        box_out += new_grid[y][x][1]
                        if new_grid[y][x][0]+new_grid[y][x][1] == 0:
                            grid[y][x] = 0
                        else:
                            in_percent = new_grid[y][x][0]/(float(new_grid[y][x][0]+new_grid[y][x][1]))
                            if in_percent < 0.45:
                                grid[y][x] = 2
                            elif in_percent > 0.55:
                                grid[y][x] = 1
                            else:
                                grid[y][x] = 3
                if box_in+box_out > 0:
                    in_percent = box_in/(float(box_in+box_out))
                    if in_percent < 0.45:
                        subgrid[r][c] = 2
                    elif in_percent > 0.55:
                        subgrid[r][c] = 1
                    else:
                        subgrid[r][c] = 3
    else:
        for row in range(ROWS):
            for column in range(COLUMNS):
                if new_grid[row][column] != 0:
                    if grid_type.startswith('Source_Ports-'):
                        subgrid[row / GRID_LINE][column / GRID_LINE] = 2
                    elif grid_type.startswith('Destination_Ports-'):
                        subgrid[row / GRID_LINE][column / GRID_LINE] = 1

    # draw grid
    for row in range(ROWS/GRID_LINE):
        for column in range(COLUMNS/GRID_LINE):
            if subgrid[row][column] > 0:
                # outbound is red
                if subgrid[row][column] == 1:
                    COLOR = RED
                # inbound is blue
                elif subgrid[row][column] == 2:
                    COLOR = BLUE
                # between 45-55% equal is green
                elif subgrid[row][column] == 3:
                    COLOR = GREEN
                # this case should never happen
                else:
                    COLOR = BLACK
                if ROWS/GRID_LINE == 17:
                    pygdraw.rect(screen,
                                 COLOR,
                                 [(MARGIN + WIDTH) * column * GRID_LINE + MARGIN-1,
                                 (MARGIN + HEIGHT) * row * GRID_LINE + MARGIN-1,
                                 (WIDTH*19)+MARGIN,
                                 (HEIGHT*19)+MARGIN])
                else:
                    pygdraw.rect(screen,
                                 COLOR,
                                 [(MARGIN + WIDTH) * column * GRID_LINE + MARGIN-1,
                                 (MARGIN + HEIGHT) * row * GRID_LINE + MARGIN-1,
                                 (WIDTH*18)+MARGIN-2,
                                 (HEIGHT*18)+MARGIN-2])

    # draw cells
    for row in range(ROWS):
        for column in range(COLUMNS):
            color = WHITE
            if grid[row][column] == 1:
                color = RED
            elif grid[row][column] == 2:
                color = BLUE
            elif grid[row][column] == 3:
                color = GREEN
            cell = pygdraw.rect(screen,
                                    color,
                                    [(MARGIN + WIDTH) * column + MARGIN,
                                     (MARGIN + HEIGHT) * row + MARGIN,
                                     WIDTH,
                                     HEIGHT])
            if grid[row][column] == 1:
                screen.blit(download, cell)
            if grid[row][column] == 2:
                screen.blit(upload, cell)
            if grid[row][column] == 3:
                screen.blit(bidirectional, cell)

    pygdisplay.flip()
    rect = pygRect(0, 0, W_HEIGHT, W_WIDTH)
    sub = screen.subsurface(rect)
    pygimage.save(sub, "www/static/img/maps/map_" + "_".join(grid_type.split()) + ".jpg")
    pygquit()

if __name__ == "__main__":
    print interpolate_tuple((0,255,255), (255,0,0), 100)
