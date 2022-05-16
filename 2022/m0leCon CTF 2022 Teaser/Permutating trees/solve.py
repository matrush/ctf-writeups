from pwn import *

class Node:
    def __init__(self, value):
        self.value = value
        self.children = []

    def setChildren(self, children):
        assert len(children) >= 1 and len(children) <= 2
        self.children = children

def dfs(pre_order, post_order, node):
    if len(pre_order) == 1:
        assert len(post_order) == 1
        return
    if pre_order[1] == post_order[-2]:
        child = Node(pre_order[1])
        node.setChildren([child])
        dfs(pre_order[1:], post_order[:-1], child)
    else:
        left_child = Node(pre_order[1])
        right_child = Node(post_order[-2])
        node.setChildren([left_child, right_child])
        dfs(pre_order[1:pre_order.index(right_child.value)], post_order[:post_order.index(left_child.value) + 1], left_child)
        dfs(pre_order[pre_order.index(right_child.value):], post_order[post_order.index(left_child.value) + 1:-1], right_child)

def dp(node, from_left, memo):
    if (node.value, from_left) in memo:
        return memo[(node.value, from_left)]
    if len(node.children) == 2:
        memo[(node.value, from_left)] = (dp(node.children[0], 1, memo)[0] + dp(node.children[1], 0, memo)[0] + 1, from_left)
    elif len(node.children) == 1:
        child = node.children[0]
        left_value = dp(child, 1, memo)[0] + (1 if from_left else 0)
        right_value = dp(child, 0, memo)[0] + (0 if from_left else 1)
        if left_value > right_value:
            memo[(node.value, from_left)] = (left_value, 1)
        else:
            memo[(node.value, from_left)] = (right_value, 0)
    else:
        memo[(node.value, from_left)] = (0, from_left)
    return memo[(node.value, from_left)]

def midOrder(node, path, from_left, memo):
    if len(node.children) == 2:
        midOrder(node.children[0], path, 1, memo)
        path.append(node.value)
        midOrder(node.children[1], path, 0, memo)
    elif len(node.children) == 1:
        go_left = memo[(node.value, from_left)][1]
        if go_left:
            midOrder(node.children[0], path, 1, memo)
        path.append(node.value)
        if not go_left:
            midOrder(node.children[0], path, 0, memo)
    else:
        path.append(node.value)

def main(args):
    p = remote("challs.m0lecon.it", 12345)
    p.recvuntil(b'start!\n\n')
    while True:
        first_line = p.recvline().strip()
        if b'ptm{' in first_line:
            flag = first_line.decode()
            assert flag == 'ptm{wdxv8s3nzwkrj4z7}'
            print(flag)
            break
        pre_order_str = first_line
        post_order_str = p.recvline().strip()
        pre_order = [int(x) for x in pre_order_str.split()]
        post_order = [int(x) for x in post_order_str.split()]
        root = Node(pre_order[0])
        dfs(pre_order, post_order, root)
        memo = {}
        dp(root, 1, memo)
        path = []
        midOrder(root, path, 1, memo)
        result = ' '.join([str(x) for x in path])
        p.sendline(result.encode())

    sys.exit(0)

if __name__ == "__main__":
	main(sys.argv)
