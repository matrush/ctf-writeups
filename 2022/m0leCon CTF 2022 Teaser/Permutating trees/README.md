# Permutating trees

## Challenge [[Link]](https://ctftime.org/task/21254)
> My gardener loves to prune in a very particular way
>
> `nc challs.m0lecon.it 12345`
>
> Author: @marS
> ```py
> Welcome!
> In this challenge we are working with binary trees.
>
> Let's define the straigthness of a node:
> given 3 nodes, x, y and z, such that x is y's parent and y is z's parent, the straightness of z is 1 if and only if (z is y's left child and y is x's left child) or (z is y's right child and y is x's right child), and it is 0 otherwise.
> The straightness of a root's child is 1 for the left child and 0 for the right child.
> The straightness of the root node is 0.
>
> A tree with n nodes has integer node labels between 0 and n-1.
>
> For each test case, you are given as input two lines, that are space-separated list of integers (the nodes' labels):
> - the first one contains the preorder visit of the tree
> - the second one contains the postorder visit of the tree
>
> Among the binary trees that have these preorder and postorder visits, you have to find the one that maximizes the sum of his nodes' straightnesses, and give as output its inorder visit, as space-separated nodes' labels on a single line.
>
> Constraints:
> 5 <= n <= 200000
> 10 seconds time limit (server side)
>
> Example (two input rows and one output row):
> 0 1 2 6 3 4 8 5 7
> 6 2 8 4 7 5 3 1 0
> 6 2 1 8 4 3 5 7 0
>
> Let's start!
>
> 0 1 2 6 3 4 8 5 7
> 6 2 8 4 7 5 3 1 0
> ```

## Solution

This one is an algorithmic problem. Given the pre-order and the post-order traversal result, one needs to find a tree that has the maximized straightness score.

First, it's not hard to know that from pre-order and post-order, one can easily recover the parent/child relationship for each node. Furthermore, for a node that has 2 children, it can be uniquely determined which one is the left child and which one is the right child. The only remaining unknown part is those nodes with only one child, whether their child is a left child or a right child.

This can be solved via a simple dynamic programming way, or the greedy way. I haven't verified the correctness of greedy but it seems to be working. Basically for `x`->`y`->`z`, if `y` is `x`'s left child, then `z` should be `y`'s left child too, and vice versa for the right child. Since if they are different, then you lose 1 straightness score, and for `z`'s child, you can regain at maximum 1 straightness score, which is no better.

For dynamic programming, we define `dp[node][is_left]` as the maximum score that `node`'s subtree has when the `node` is its parent's left/right child based on the `is_left` state. Thus we have:
- If `node` has 2 children:
    - `dp[node][is_left] = dp[node.left_child][1] + dp[node.right_child][0] + 1;`
    - Regardless of `is_left`'s value, either `left_child` or `right_child` can get 1 score.
- If `node` only have 1 child:
    - `dp[node][is_left] = max(dp[node.child][1] + (1 if is_left else 0), dp[node.child][0] + (0 if is_left else 1))`
    - Putting child at left/right respectively and calculate its maximum.

From the dp we can get the maximum value, and we need to record the path along the way.

## Flag
`ptm{wdxv8s3nzwkrj4z7}`
