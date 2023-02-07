use bitfield::bitfield;

bitfield! {
    pub struct DebugCtl(u64);

    pub last_branch_record, set_last_branch_record: 0, 0;
    pub branch_single_step, set_branch_single_step: 1, 1;

    // Performance Monitoring Pin Control
    pub pb0, set_pb0: 2, 2;
    pub pb1, set_pb1: 3, 3;
    pub pb2, set_pb2: 4, 4;
    pub pb3, set_pb3: 5, 5;
}