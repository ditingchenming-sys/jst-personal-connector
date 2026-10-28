"""经源码核对的只读请求目录；目录外请求默认拒绝。"""

ITEM_URL = "https://apiweb.erp321.com/webapi/ItemApi/ItemSku/GetPageListV2"
PURCHASE_URL = "https://www.erp321.com/app/scm/purchase/purchasemode.aspx"
ORDER_URL = "https://www.erp321.com/app/order/order/list.aspx"
FMS_BASE = "https://api.erp321.com/fms/api"
FMS_READS = {
    f"{FMS_BASE}/supplierclear?getSupplierClearInoutList": "getSupplierClearInoutList",
    f"{FMS_BASE}/payable?getPayableList": "getPayableList",
    f"{FMS_BASE}/common?getPayableItemList": "getPayableItemList",
    f"{FMS_BASE}/payablereport?getPayablePaidTransactionReport": "getPayablePaidTransactionReport",
    f"{FMS_BASE}/payablereport?getPayableInvoiceReport": "getPayableInvoiceReport",
    f"{FMS_BASE}/payment?getPaymentList": "getPaymentList",
    f"{FMS_BASE}/payment?getPayment": "getPayment",
    f"{FMS_BASE}/payment?getPrepayItemList": "getPrepayItemList",
    f"{FMS_BASE}/payment?getPrepayUnDeductedList": "getPrepayUnDeductedList",
}

QUERY_NAMES = {
    "Q01": "商品资料与库存", "Q02": "商品精准查询及关联商品", "Q03": "未发货订单",
    "Q04": "采购单", "Q05": "采购付款、收货及退货记录", "Q06": "按商品进销存报表",
    "Q07": "销售明细", "Q08": "分销销售及供销商列表", "Q09": "供应商清算明细",
    "Q10": "应付单及关联记录", "Q11": "付款单、预付款及抵扣", "Q12": "供应商应付看板",
    "Q13": "订单备注回查", "Q14": "操作日志",
}
WRITE_NAMES = {
    "W01": "清算生成应付及确认生效", "W02": "生成付款单", "W03": "采购单备注维护",
    "W04": "采购入库及退货单表头备注", "W05": "平台商品绑定、国标码及标签维护",
    "W06": "应付看板刷新", "W07": "触发懒人计划",
}
