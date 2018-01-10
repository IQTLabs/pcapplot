from pygame import display as pygdisplay
from pygame import draw as pygdraw
from pygame import font as pygfont
from pygame import image as pygimage
from pygame import init as pyginit
from pygame import quit as pygquit
from pygame import Rect as pygRect

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
    GRID_LINE = 16
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
    for row in range(ROWS):
        for column in range(COLUMNS):
            if grid[row][column] != 0:
                subgrid[row / GRID_LINE][column / GRID_LINE] = 1

    # draw grid
    for row in range(ROWS/GRID_LINE):
        for column in range(COLUMNS/GRID_LINE):
            if subgrid[row][column] == 1:
                pygdraw.rect(screen,
                                 BLACK,
                                 [(MARGIN + WIDTH) * column * GRID_LINE + MARGIN-1,
                                  (MARGIN + HEIGHT) * row * GRID_LINE + MARGIN-1,
                                  (WIDTH*18)+MARGIN-2,
                                  (HEIGHT*18)+MARGIN-2])
                pygdraw.rect(screen,
                                 BLACK,
                                 [(MARGIN + WIDTH) * column * GRID_LINE + MARGIN,
                                  (MARGIN + HEIGHT) * row * GRID_LINE + MARGIN,
                                  (WIDTH*18)+MARGIN-4,
                                  (HEIGHT*18)+MARGIN-4])

    # draw cells
    for row in range(ROWS):
        for column in range(COLUMNS):
            color = WHITE
            if grid[row][column] == 1:
                color = (255, 0, 255)
            elif grid[row][column] == 2:
                color = (255, 0, 255)
            elif grid[row][column] == 3:
                color = (0, 255, 255)
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
