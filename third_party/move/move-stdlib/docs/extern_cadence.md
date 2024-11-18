
<a id="0x1_extern_cadence"></a>

# Module `0x1::extern_cadence`

The <code><a href="extern_cadence.md#0x1_extern_cadence">extern_cadence</a></code> module defines the <code><a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">ExternCadence</a></code> type which represents an external type in cadence


-  [Struct `ExternCadence`](#0x1_extern_cadence_ExternCadence)
-  [Function `create_composite`](#0x1_extern_cadence_create_composite)
-  [Function `get_member`](#0x1_extern_cadence_get_member)
-  [Function `set_member`](#0x1_extern_cadence_set_member)
-  [Function `internal_create_composite`](#0x1_extern_cadence_internal_create_composite)
-  [Function `internal_get_member`](#0x1_extern_cadence_internal_get_member)
-  [Function `internal_set_member`](#0x1_extern_cadence_internal_set_member)


<pre><code><b>use</b> <a href="string.md#0x1_string">0x1::string</a>;
</code></pre>



<a id="0x1_extern_cadence_ExternCadence"></a>

## Struct `ExternCadence`

An <code><a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">ExternCadence</a></code> type simply holds an id to interface with cadence.


<pre><code><b>struct</b> <a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">ExternCadence</a> <b>has</b> <b>copy</b>, drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>id: u64</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a id="0x1_extern_cadence_create_composite"></a>

## Function `create_composite`

Creates a new ExternCadence object.


<pre><code><b>public</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_create_composite">create_composite</a>(<b>address</b>: &<a href="string.md#0x1_string_String">string::String</a>, kind: u64, identifier: &<a href="string.md#0x1_string_String">string::String</a>): <a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">extern_cadence::ExternCadence</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_create_composite">create_composite</a>(<b>address</b>: &<a href="string.md#0x1_string_String">string::String</a>, kind: u64, identifier: &<a href="string.md#0x1_string_String">string::String</a>): <a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">ExternCadence</a> {
  <b>let</b> id = <a href="extern_cadence.md#0x1_extern_cadence_internal_create_composite">internal_create_composite</a>(<a href="string.md#0x1_string_bytes">string::bytes</a>(<b>address</b>), kind, <a href="string.md#0x1_string_bytes">string::bytes</a>(identifier));
  <a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">ExternCadence</a>{id}
}
</code></pre>



</details>

<a id="0x1_extern_cadence_get_member"></a>

## Function `get_member`

Get the value of an external member with string type.


<pre><code><b>public</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_get_member">get_member</a>(e: &<a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">extern_cadence::ExternCadence</a>, field_name: &<a href="string.md#0x1_string_String">string::String</a>): <a href="string.md#0x1_string_String">string::String</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_get_member">get_member</a>(e: &<a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">ExternCadence</a>, field_name: &<a href="string.md#0x1_string_String">string::String</a>): <a href="string.md#0x1_string_String">string::String</a> {
  <b>let</b> res = <a href="extern_cadence.md#0x1_extern_cadence_internal_get_member">internal_get_member</a>(e.id, <a href="string.md#0x1_string_bytes">string::bytes</a>(field_name));
  <a href="string.md#0x1_string_utf8">string::utf8</a>(res)
}
</code></pre>



</details>

<a id="0x1_extern_cadence_set_member"></a>

## Function `set_member`

Set the value of an external member with string type.


<pre><code><b>public</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_set_member">set_member</a>(e: &<a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">extern_cadence::ExternCadence</a>, field_name: &<a href="string.md#0x1_string_String">string::String</a>, value: &<a href="string.md#0x1_string_String">string::String</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_set_member">set_member</a>(e: &<a href="extern_cadence.md#0x1_extern_cadence_ExternCadence">ExternCadence</a>, field_name: &<a href="string.md#0x1_string_String">string::String</a>, value: &<a href="string.md#0x1_string_String">string::String</a>) {
  <a href="extern_cadence.md#0x1_extern_cadence_internal_set_member">internal_set_member</a>(e.id, <a href="string.md#0x1_string_bytes">string::bytes</a>(field_name), <a href="string.md#0x1_string_bytes">string::bytes</a>(value));
}
</code></pre>



</details>

<a id="0x1_extern_cadence_internal_create_composite"></a>

## Function `internal_create_composite`



<pre><code><b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_internal_create_composite">internal_create_composite</a>(<b>address</b>: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;, kind: u64, identifier: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>native</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_internal_create_composite">internal_create_composite</a>(<b>address</b>: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;, kind: u64, identifier: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;): u64;
</code></pre>



</details>

<a id="0x1_extern_cadence_internal_get_member"></a>

## Function `internal_get_member`



<pre><code><b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_internal_get_member">internal_get_member</a>(id: u64, field_name: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;): <a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>native</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_internal_get_member">internal_get_member</a>(id: u64, field_name: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;): <a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;;
</code></pre>



</details>

<a id="0x1_extern_cadence_internal_set_member"></a>

## Function `internal_set_member`



<pre><code><b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_internal_set_member">internal_set_member</a>(id: u64, field_name: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;, value: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>native</b> <b>fun</b> <a href="extern_cadence.md#0x1_extern_cadence_internal_set_member">internal_set_member</a>(id: u64, field_name: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;, value: &<a href="vector.md#0x1_vector">vector</a>&lt;u8&gt;): bool;
</code></pre>



</details>


[//]: # ("File containing references which can be used from documentation")
