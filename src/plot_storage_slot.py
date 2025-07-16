
import matplotlib.pyplot as plt
import numpy as np

# 数据
# slot-num, percentage
data = [
    ('7', 25.66),
    ('1', 24.13),
    ('2', 12.56),
    ('3', 9.68),
    ('18', 8.08),
    ('4', 7.71),
    ('10', 4.03),
    ('5', 2.19),
    ('8', 1.32),
    ('6', 1.29),
    ('9', 0.71),
    ('11', 0.70),
    ('12', 0.65),
    ('17', 0.33),
    ('21', 0.14),
    ('14', 0.14),
    ('15', 0.13),
    ('19', 0.11),
    ('13', 0.08),
    ('16', 0.06),
    ('25', 0.04),
    ('41', 0.04),
    ('91', 0.04),
    ('22', 0.04),
    ('20', 0.03),
    ('23', 0.03),
    ('40', 0.03),
    ('82', 0.01),
    ('39', 0.01),
    ('43', 0.01),
    ('24', 0.01),
    ('37', 0.01),
    ('101', 0.01),
    ('102', 0.01),
    ('81', 0.01)
]

# average num
average_num = 0
for item in data:
    num = int(item[0])
    percentage = item[1]/100
    average_num += num * percentage
print(f"average num: {average_num}")
average_size = average_num *32
print(f"average size: {average_size} byte")

# 分类和统计
categories = {
    '1': 0.0,
    '2':0.0,
    '3': 0.0,
    '4-10': 0.0,
    '10-20': 0.0,
    '20-30': 0.0,
    '>30': 0.0
    # '30-50': 0.0,
    # '50-100': 0.0,
    # '100-200': 0.0,
    # '200-400': 0.0,
    # '>400': 0.0
}

# Categorize data
for item in data:
    depth = int(item[0])
    percentage = item[1]
    if depth == 1 :
        categories['1'] += percentage
    elif depth == 2 :
        categories['2'] += percentage
    elif depth == 3:
        categories['3'] += percentage
    elif 4 <= depth < 10:
        categories['4-10'] += percentage
    elif 10 <= depth < 20:
        categories['10-20'] += percentage
    elif 20 <= depth < 30:
        categories['20-30'] += percentage
    else:
        categories['>30'] += percentage
    # elif 50 <= depth < 100:
    #     categories['50-100'] += percentage
    # elif 100 <= depth < 200:
    #     categories['100-200'] += percentage
    # elif 200 <= depth < 400:
    #     categories['200-400'] += percentage
    # else:
    #     categories['>400'] += percentage

# 提取分类标签和百分比
labels = list(categories.keys())
sizes = list(categories.values())

# 创建饼状图
plt.figure(figsize=(10, 10))  # 设置图表大小
plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, radius=0.2)  # 绘制饼状图
plt.title('Contract Storage Slot Num Distribution')  # 设置图表标题
plt.axis('equal')  # 使饼状图为圆形

# 显示图例
plt.legend(title="slot-num", loc="lower left", prop={'size': 12}, bbox_to_anchor=(-0.1, 0))

plt.tight_layout()  # 调整布局
# save
plt.savefig('storage_slot_distribution.png', bbox_inches='tight')


# 创建柱状图
fig, ax = plt.subplots(figsize=(10, 6))  # 设置图表大小

# 绘制柱状图
bar_positions = np.arange(len(labels))  # 柱状图的位置
ax.bar(bar_positions, sizes, width=0.5, label=labels)  # 画柱状图

# 设置图表样式
ax.set_title('Contract Storage Slot Num Distribution')  # 设置图表标题
ax.set_xlabel('Slot Num Range')  # 设置x轴标签
ax.set_ylabel('Percentage (%)')  # 设置y轴标签

# 设置x轴标签和刻度
ax.set_xticks(bar_positions)
ax.set_xticklabels(labels, rotation=45)  # 旋转x轴标签45度

# 添加数据标签
for i, v in enumerate(sizes):
    ax.text(bar_positions[i], v + 1, str(round(v, 2)) + '%',  # 显示百分比并保留两位小数
            ha='center', va='bottom', fontsize=10)

# 添加图例
ax.legend(title="Slot Range", loc="upper right")

plt.tight_layout()  # 调整布局
plt.savefig('storage_slot_distribution_bar.png', bbox_inches='tight')  # 保存图表