import random
def draw_board(board):
    for row in board:
        print(" | ".join(row))
        print("-" * 9)
def check_winner(board,current_player):
    for row in board:
        if row[0] == row[1] == row[2] != ' ':
            return row[0]
    for col in range(3):
        if board[0][col] == board[1][col] == board[2][col] != ' ':
            return board[0][col]
    if board[0][0] == board[1][1] == board[2][2] != ' ':
        return board[0][0]
    if board[0][2] == board[1][1] == board[2][0] != ' ':
        return board[0][2]
    return None
def available_moves(board):
    return [(r, c) for r in range(3) for c in range(3) if board[r][c] == " "]
def computer_move(board):
    row, col = random.choice(available_moves(board))
    return row, col
def play_ttt():
    board = [[" " for _ in range(3)] for _ in range(3)]  
    current_player = "X"  
    print("Tic-Tac-Toe Game")
    draw_board(board)
    while True:
        if current_player == "X":
            print("Player X's turn")
            row, col = computer_move(board)
        else:
            print("Player O's turn")
            row, col = computer_move(board)
        board[row][col] = current_player
        draw_board(board)
        if check_winner(board, current_player):
            print(f"Player {current_player} wins!")
            break
        if not available_moves(board):
            print("It's a draw!")
            break
        current_player = "O" if current_player == "X" else "X"
play_ttt()