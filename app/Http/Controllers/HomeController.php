<?php

namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;
class HomeController extends Controller
{
    public function getproducts(Request $request)
    {
       
  
       try {
    $entireTable = Product::where('MODEL', $request->model)->first();

    if ($entireTable) {
        $entireTable = $entireTable->toArray();

        // List of columns to format to 2 decimal places
        $columnsToFormat = [
            'SALE', 'PURCHASE', 'ADJUSTMENT', 'RETURN', 'IN_FBA', 'FBA_SALE_QTY', 'FBA_RETURN_QTY',
            'TRANSIT', 'BALANCE', 'IN_HAND', 'AVG_PRICE', 'VALUE', 'LAST_PURCHASE',
            'LAST_PURCHASE_QTY', 'LAST_SOLD_PRICE', 'SHIPPING_PRICE', 'SHIPPING_PAID',
            'NET_PROFIT', 'PORTAL_CHARGES', 'SPONSORD_AD_FEE', 'ADD_PERCENT',
            'RATE_2_RATE_AMZ', 'RATE_2_RATE_EBAY', 'TOTAL_NET_PROFIT', 'AVG_PROFIT',
            'MIN_PURCHASE_PRICE', 'MAX_SOLD_PRICE', 'LAST_RETURN_SELLING_PRICE',
            'LAST_ADJ_QTY', 'SETUP_AMAZON_CHARGES', 'SETUP_AMZ_SHIPPING_PAID',
            'SETUP_EBAY_SHIPPING_PRICE', 'SETUP_EBAY_CHARGES', 'SETUP_EBAY_SHIPPING_PAID'
        ];

        foreach ($columnsToFormat as $col) {
            if (isset($entireTable[$col]) && is_numeric($entireTable[$col])) {
                $entireTable[$col] = number_format((float)$entireTable[$col], 2, '.', '');
            }
        }
    }

    return response()->json([
        'Data' => $entireTable
    ]);
} catch (\Exception $e) {
    return response()->json([
        'Error' => $e->getMessage()
    ]);
}
    }
    public function Zager(Request $request){
    
    try {
        $purchaseOrderNumber = Cache::increment('purchase_order_number', 1, 1);
        $currentDate = date('dMY');
        
        $completePurchaseOrderNumber = 'NWOW' . $currentDate . '-' . $purchaseOrderNumber . '-MOB-APP';

        $response = Http::withHeaders([
            'Apikey' => env('Apikey'),
        ])->withoutVerifying()->post(env('Order_Url'), [
            'purchase_order_number' => $completePurchaseOrderNumber,
            'order_lines' => [
                [
                    'product_number' => $request->product_number,
                    'amount' => 1,
                ],
            ],
        'shipping_method' => 'UPS',
        'customer_delivery_name' => 'Upload Later',
        'customer_delivery_address' => 'Upload Later',
        'customer_delivery_postal' => 'Upload Later',
        'customer_delivery_city' => 'Upload Later',
        'customer_delivery_country' => 'US',
        'customer_delivery_state' => 'UL',
        'customer_delivery_phone' => ''
        ]);
        $result = $response->json();
       
        if (!$result) {
            // If the response is empty or null, return an empty array
            $result = [];
        }

        return $result;
    } catch (\Exception $e) {
        dd($e);
    }
}

public function getSuggested(Request $request)
{
    // Validate the input
    $validated = $request->validate([
        'model' => 'required|string',
        'suggested_price' => 'required|numeric',
        'percentage' => 'required|numeric'
    ]);

    $model = $validated['model'];
    $suggested = $validated['suggested_price'];
    $percentage = $validated['percentage'];

    $product = Product::where('model', $model)->first();

    if (!$product) {
        return response()->json([
            'error' => 'Product not found'
        ], 404);
    }

    // Calculations (same as your SQL logic)
    $ebayPrice = round(
        ($suggested - $product->SETUP_EBAY_SHIPPING_PAID)
        - ((($suggested + $product->SETUP_EBAY_SHIPPING_PRICE) * $product->SETUP_EBAY_CHARGES) / 100)
        - $product->LAST_PURCHASE + $product->SETUP_EBAY_SHIPPING_PRICE
        - ((($suggested + $product->SETUP_EBAY_SHIPPING_PRICE) * $percentage) / 100),
    2);

    $amzPrice = round(
        ($suggested - $product->SETUP_EBAY_SHIPPING_PAID)
        - ((($suggested + $product->SETUP_AMZ_SHIPPING_PAID) * $product->SETUP_AMAZON_CHARGES) / 100)
        - $product->LAST_PURCHASE
        - ((($suggested) * $percentage) / 100),
    2);

    return response()->json([
        'ebay_price' => number_format($ebayPrice,2),
        'amazon_price' => number_format($amzPrice,2)
    ]);
}
}
