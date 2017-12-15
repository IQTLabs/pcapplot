import pygame
import time

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
GREEN = (0, 255, 0)
RED = (255, 0, 0)
BLUE = (0, 0, 255)

WIDTH = 9
HEIGHT = 9
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

grid[1][5] = 1
grid[40][34] = 2
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
screen.fill(BLACK)

for row in range(ROWS):
    for column in range(COLUMNS):
        color = BLACK
        if grid[row][column] == 1:
            color = BLUE
        elif grid[row][column] == 2:
            color = RED
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
