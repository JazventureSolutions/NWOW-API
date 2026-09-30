<?php

namespace App\Http\Controllers;

use App\Models\Products;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ProductController extends Controller
{
public function getproducts()
{
    $entireTable = Products::all();
    return response()->json([
        'request' => $entireTable
    ]);

}

}
