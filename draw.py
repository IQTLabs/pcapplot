import pygame
import time

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

def draw():
    BLACK = (0, 0, 0)
    WHITE = (255, 255, 255)
    GREEN = (0, 255, 0)
    RED = (255, 0, 0)
    BLUE = (0, 0, 255)

    WIDTH = 9
    HEIGHT = 9
    GRID_LINE = 16
    ROWS = 256
    COLUMNS = 256
    MARGIN = 1
    W_HEIGHT = 2561
    W_WIDTH = 2561
    WINDOW_SIZE = [W_HEIGHT, W_WIDTH]

    grid = []
    for row in range(ROWS):
        grid.append([])
        for column in range(COLUMNS):
            grid[row].append(0)
    subgrid = []
    for row in range(ROWS/GRID_LINE):
        subgrid.append([])
        for column in range(COLUMNS/GRID_LINE):
            subgrid[row].append(0)

    # MANIPULATE DATA HERE
    grid[1][15] = 1
    grid[2][32] = 2
    grid[3][200] = 1
    grid[100][3] = 2
    grid[99][99] = 1
    grid[240][200] = 2
    grid[45][250] = 1

    pygame.init()

    myfont = pygame.font.SysFont('Times New Roman', 9)
    download=myfont.render('D', True, WHITE)
    upload=myfont.render('U', True, WHITE)
    bidirectional=myfont.render('B', True, WHITE)
    screen = pygame.display.set_mode(WINDOW_SIZE)
    pygame.display.set_caption("PCAP Plot")
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
                pygame.draw.rect(screen,
                                 BLACK,
                                 [(MARGIN + WIDTH) * column * GRID_LINE + MARGIN-1,
                                  (MARGIN + HEIGHT) * row * GRID_LINE + MARGIN-1,
                                  (WIDTH*18)+MARGIN-2,
                                  (HEIGHT*18)+MARGIN-2])
                pygame.draw.rect(screen,
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
                color = (column, 0, 255)
            elif grid[row][column] == 2:
                color = (255, 0, column)
            cell = pygame.draw.rect(screen,
                                    color,
                                    [(MARGIN + WIDTH) * column + MARGIN,
                                     (MARGIN + HEIGHT) * row + MARGIN,
                                     WIDTH,
                                     HEIGHT])
            if grid[row][column] == 1:
                screen.blit(download, cell)
            if grid[row][column] == 2:
                screen.blit(upload, cell)

    pygame.display.flip()

    done = False
    while not done:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                done = True
        time.sleep(1)

    rect = pygame.Rect(0, 0, W_HEIGHT, W_WIDTH)
    sub = screen.subsurface(rect)
    pygame.image.save(sub, "screenshot.jpg")
    pygame.quit()

if __name__ == "__main__":
    draw()
    print interpolate_tuple((0,255,255), (255,0,0), 100)
